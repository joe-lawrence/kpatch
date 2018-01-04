__kpatch_funcs = ADDR(.kpatch.funcs);
__kpatch_funcs_end = ADDR(.kpatch.funcs) + SIZEOF(.kpatch.funcs);

#ifdef __KPATCH_MODULE__
__kpatch_dynrelas = ADDR(.kpatch.dynrelas);
__kpatch_dynrelas_end = ADDR(.kpatch.dynrelas) + SIZEOF(.kpatch.dynrelas);
__kpatch_checksum = ADDR(.kpatch.checksum);
#endif

SECTIONS
{
#ifdef __KPATCH_MODULE__
  .kpatch.hooks.load : {
    __kpatch_hooks_load = . ;
    *(.kpatch.hooks.load)
    __kpatch_hooks_load_end = . ;
    /*
     * Pad the end of the section with zeros in case the section is empty.
     * This prevents the kernel from discarding the section at module
     * load time. __kpatch_hooks_load_end will still point to the end of
     * the section before the padding.  If the .kpatch.hooks.load section
     * is empty, __kpatch_hooks_load equals __kpatch_hooks_load_end.
     */
    QUAD(0);
  }
  .kpatch.hooks.unload : {
    __kpatch_hooks_unload = . ;
    *(.kpatch.hooks.unload)
    __kpatch_hooks_unload_end = . ;
    QUAD(0);
  }
#else
  .kpatch.hooks.pre_patch : {
    __kpatch_hooks_pre_patch = . ;
    *(.kpatch.hooks.pre_patch)
    __kpatch_hooks_pre_patch_end = . ;
    QUAD(0);
  }
  .kpatch.hooks.post_patch : {
    __kpatch_hooks_post_patch = . ;
    *(.kpatch.hooks.post_patch)
    __kpatch_hooks_post_patch_end = . ;
    QUAD(0);
  }
  .kpatch.hooks.pre_unpatch : {
    __kpatch_hooks_pre_unpatch = . ;
    *(.kpatch.hooks.pre_unpatch)
    __kpatch_hooks_pre_unpatch_end = . ;
    QUAD(0);
  }
  .kpatch.hooks.post_unpatch : {
    __kpatch_hooks_post_unpatch = . ;
    *(.kpatch.hooks.post_unpatch)
    __kpatch_hooks_post_unpatch_end = . ;
    QUAD(0);
  }
#endif
  .kpatch.force : {
    __kpatch_force_funcs = . ;
    *(.kpatch.force)
    __kpatch_force_funcs_end = . ;
    QUAD(0);
  }
}
