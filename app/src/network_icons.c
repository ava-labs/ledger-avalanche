#include "os_utils.h"
#include "os_pic.h"

// Replace function from ethereum app to skip icon generation
#if defined(TARGET_STAX)
#include "nbgl_types.h"
#include "glyphs.h"

const nbgl_icon_details_t *get_network_icon_from_chain_id(const uint64_t *chain_id) {
    UNUSED(chain_id);
    const nbgl_icon_details_t *icon = NULL;

    icon = &ICONGLYPH;
    if (icon == NULL) {
        PRINTF("%s(%s) returned NULL!\n", __func__, (caller_icon ? "true" : "false"));
    }
    return icon;
}
#endif
