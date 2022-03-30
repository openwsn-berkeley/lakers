__flash_cca__ = FLASH_CCA;

SECTIONS
{
  .flash_cca ORIGIN(FLASH) + LENGTH(FLASH) - 44:
  {
    *(.flash_cca.*);
    . = ALIGN(4);
  } > FLASH

  .dma_channel_config (NOLOAD):
  {
    *(.dma_channel_config.*);
    . = ALIGN(1024);
  } > RAM
}

