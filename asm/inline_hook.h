#ifndef TRAP_INLINE_HOOK_H
#define TRAP_INLINE_HOOK_H

#include <Zydis/Zydis.h>
#include <zero/singleton.h>

class CInlineHook {
#define gInlineHook zero::Singleton<CInlineHook>::getInstance()
public:
    CInlineHook();

private:
    unsigned long getCodeTail(void *address);

public:
    bool hook(void *address, void *replace, void **backup);
    bool unhook(void *address, void *backup);

private:
    bool setCodeReadonly(void *address, unsigned long size) const;
    bool setCodeWriteable(void *address, unsigned long size) const;

protected:
    ZydisDecoder mDecoder{};

private:
    unsigned long mPagesize;
};


#endif //TRAP_INLINE_HOOK_H
