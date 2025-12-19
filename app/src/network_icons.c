#include "os_pic.h"
#include "os_utils.h"
#include "zxmacros.h"

// Replace function from ethereum app to skip icon generation
#if defined(TARGET_STAX) || defined(TARGET_FLEX) || defined(TARGET_APEX_P)
#include "glyphs.h"
#include "nbgl_types.h"

const nbgl_icon_details_t *get_network_icon_from_chain_id(__Z_UNUSED const uint64_t *chain_id) {
    const nbgl_icon_details_t *icon = NULL;

    icon = &ICONGLYPH;
    if (icon == NULL) {
        PRINTF("%s(%s) returned NULL!\n", __func__, (caller_icon ? "true" : "false"));
    }
    return icon;
}
#endif
