#include <unistd.h>
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/os/procfs.h>
#include <sys/user.h>
#include <elf/symbol.h>
#include <trap/trap.h>

using EvalFrame = void *(*)(void *, void *, void *);
using EvalString = int (*)(const char *);

constexpr auto PYTHON_IMAGE = {
        "libpython",
        "bin/python",
        "uwsgi"
};

constexpr auto EVAL_STRING_SYMBOL = "PyRun_SimpleString";
constexpr auto EVAL_FRAME_SYMBOL = "PyEval_EvalFrameEx";
constexpr auto EVAL_FRAME_DEFAULT_SYMBOL = "_PyEval_EvalFrameDefault";

static EvalFrame origin = nullptr;
static EvalString eval = nullptr;

static char code[10240] = {};
static std::atomic<bool> done = false;

void *fake(void *x, void *y, void *z) {
    bool expected = false;

    if (!done && done.compare_exchange_strong(expected, true))
        eval(code);

    return origin(x, y, z);
}

int main(int argc, char **argv) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<std::string>("script", "python script");
    cmdline.addOptional("file", 'f', "load script from file");

    cmdline.parse(argc, argv);

    auto script = cmdline.get<std::string>("script");

    if (cmdline.exist("file")) {
        std::ifstream stream(script);

        if (!stream.is_open()) {
            LOG_ERROR("script does not exist");
            return -1;
        }

        script = {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
    }

    if (script.length() >= sizeof(code)) {
        LOG_ERROR("script too long");
        return -1;
    }

    strcpy(code, script.c_str());

    std::optional<zero::os::procfs::Process> process = zero::os::procfs::openProcess(getpid());

    if (!process)
        return -1;

    auto it = std::find_if(PYTHON_IMAGE.begin(), PYTHON_IMAGE.end(), [&](const auto &image) {
        return process->getImageBase(image);
    });

    if (it == PYTHON_IMAGE.end()) {
        LOG_ERROR("can't find python image");
        return -1;
    }

    std::optional<zero::os::procfs::MemoryMapping> memoryMapping = process->getImageBase(*it);

    if (!memoryMapping) {
        LOG_ERROR("can't get python image");
        return -1;
    }

    LOG_INFO("python image base: 0x%lx", memoryMapping->start);

    std::filesystem::path path = std::filesystem::path("/proc/self/root") / memoryMapping->pathname;
    std::optional<elf::Reader> reader = elf::openFile(path);

    if (!reader) {
        LOG_ERROR("open elf failed: %s", path.string().c_str());
        return -1;
    }

    std::vector<std::shared_ptr<elf::ISection>> sections = reader->sections();

    auto sit = std::find_if(
            sections.begin(),
            sections.end(),
            [](const auto &section) {
                return section->type() == SHT_DYNSYM;
            }
    );

    if (sit == sections.end()) {
        LOG_ERROR("can't find symbol section");
        return -1;
    }

    bool dynamic = reader->header()->type() == ET_DYN;

    std::vector<std::shared_ptr<elf::ISegment>> loads;
    std::vector<std::shared_ptr<elf::ISegment>> segments = reader->segments();

    std::copy_if(
            segments.begin(),
            segments.end(),
            std::back_inserter(loads),
            [](const auto &segment) {
                return segment->type() == PT_LOAD;
            }
    );

    Elf64_Addr minVA = std::min_element(
            loads.begin(),
            loads.end(),
            [](const auto &i, const auto &j) {
                return i->virtualAddress() < j->virtualAddress();
            }
    )->operator*().virtualAddress() & ~(PAGE_SIZE - 1);

    elf::SymbolTable symbolTable(*reader, *sit);

    auto symbolIterator = std::find_if(symbolTable.begin(), symbolTable.end(), [](const auto &symbol) {
        return symbol->name() == EVAL_STRING_SYMBOL;
    });

    if (symbolIterator == symbolTable.end()) {
        LOG_ERROR("can't find 'PyRun_SimpleString' function");
        return -1;
    }

    uintptr_t base = dynamic ? memoryMapping->start - minVA : 0;
    eval = (EvalString) (base + symbolIterator.operator*()->value());

    symbolIterator = std::find_if(symbolTable.begin(), symbolTable.end(), [](const auto &symbol) {
        return symbol->name() == EVAL_FRAME_DEFAULT_SYMBOL || symbol->name() == EVAL_FRAME_SYMBOL;
    });

    if (symbolIterator == symbolTable.end()) {
        LOG_ERROR("can't find 'PyEval_EvalFrameEx' and '_PyEval_EvalFrameDefault' function");
        return -1;
    }

    void *fn = (void *) (base + symbolIterator.operator*()->value());

    LOG_INFO("function address: %p", fn);

    if (trap_hook(fn, (void *) fake, (void **) &origin) < 0) {
        LOG_ERROR("hook function failed");
        return -1;
    }

    return 0;
}
