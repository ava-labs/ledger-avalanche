#include "os_utils.h"
#include "os_pic.h"

// Replace functions from ethereum app to skip icon generation and UI idle menu
#if defined(TARGET_STAX) || defined(TARGET_FLEX) || defined(TARGET_APEX_P)
#include "nbgl_types.h"
#include "glyphs.h"
#include "ui_nbgl.h"

#include "view.h"

char g_stax_shared_buffer[SHARED_BUFFER_SIZE] = {0};
nbgl_page_t *pageContext;

const nbgl_icon_details_t *get_app_icon(bool caller_icon)
{
    UNUSED(caller_icon);
    const nbgl_icon_details_t *icon = NULL;

    icon = &ICONGLYPH;
    if (icon == NULL)
    {
        PRINTF("%s(%s) returned NULL!\n", __func__, (caller_icon ? "true" : "false"));
    }
    return icon;
}

const nbgl_icon_details_t *get_network_icon_from_chain_id(const uint64_t *chain_id)
{
    UNUSED(chain_id);
    return get_app_icon(false);
}

// Redirect ui_idle from eth app to ours UI
void ui_idle(void)
{
    view_idle_show(0, NULL);
}
#endif
