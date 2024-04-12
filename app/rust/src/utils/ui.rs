#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "derive-debug", derive(Debug))]
#[repr(u8)]
pub enum ViewError {
    Unknown,
    NoData,
    Reject,
}

pub trait Viewable {
    const IS_ADDRESS: bool = false;

    /// Return the number of items to render
    fn num_items(&mut self) -> Result<u8, ViewError>;

    /// Render `item_idx` into `title` and `message`
    ///
    /// If an item is too long to render in the output, the number of "pages" is returned,
    /// and each page can be retrieved via the `page_idx` parameter
    fn render_item(
        &mut self,
        item_idx: u8,
        title: &mut [u8],
        message: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ViewError>;

    /// Called when the last item shown has been "accepted"
    ///
    /// `out` is the apdu_buffer
    ///
    /// Return is number of bytes written to out and the return code
    fn accept(&mut self, apdu_response: &mut [u8]) -> (usize, u16);

    /// Called when the last item shows has been "rejected"
    /// `out` is the apdu_buffer
    ///
    /// Return is number of bytes written to out and the return code
    fn reject(&mut self, apdu_response: &mut [u8]) -> (usize, u16);
}
