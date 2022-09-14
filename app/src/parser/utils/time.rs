/*******************************************************************************
*   (c) 2021 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use crate::parser::{u64_to_str, u8_to_str, FORMATTED_STR_DATE_LEN};
use crate::sys::{pic_str, PIC};
use arrayvec::ArrayVec;
use arrayvec::CapacityError;

use lexical_core::Number;

const MONTH_DAYS: &[u8; 12] = &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

const YEAR_LOOKUP: &[u32; 400] = &[
    0, 365, 730, 1096, 1461, 1826, 2191, 2557, 2922, 3287, 3652, 4018, 4383, 4748, 5113, 5479,
    5844, 6209, 6574, 6940, 7305, 7670, 8035, 8401, 8766, 9131, 9496, 9862, 10227, 10592, 10957,
    11323, 11688, 12053, 12418, 12784, 13149, 13514, 13879, 14245, 14610, 14975, 15340, 15706,
    16071, 16436, 16801, 17167, 17532, 17897, 18262, 18628, 18993, 19358, 19723, 20089, 20454,
    20819, 21184, 21550, 21915, 22280, 22645, 23011, 23376, 23741, 24106, 24472, 24837, 25202,
    25567, 25933, 26298, 26663, 27028, 27394, 27759, 28124, 28489, 28855, 29220, 29585, 29950,
    30316, 30681, 31046, 31411, 31777, 32142, 32507, 32872, 33238, 33603, 33968, 34333, 34699,
    35064, 35429, 35794, 36160, 36525, 36890, 37255, 37621, 37986, 38351, 38716, 39082, 39447,
    39812, 40177, 40543, 40908, 41273, 41638, 42004, 42369, 42734, 43099, 43465, 43830, 44195,
    44560, 44926, 45291, 45656, 46021, 46387, 46752, 47117, 47482, 47847, 48212, 48577, 48942,
    49308, 49673, 50038, 50403, 50769, 51134, 51499, 51864, 52230, 52595, 52960, 53325, 53691,
    54056, 54421, 54786, 55152, 55517, 55882, 56247, 56613, 56978, 57343, 57708, 58074, 58439,
    58804, 59169, 59535, 59900, 60265, 60630, 60996, 61361, 61726, 62091, 62457, 62822, 63187,
    63552, 63918, 64283, 64648, 65013, 65379, 65744, 66109, 66474, 66840, 67205, 67570, 67935,
    68301, 68666, 69031, 69396, 69762, 70127, 70492, 70857, 71223, 71588, 71953, 72318, 72684,
    73049, 73414, 73779, 74145, 74510, 74875, 75240, 75606, 75971, 76336, 76701, 77067, 77432,
    77797, 78162, 78528, 78893, 79258, 79623, 79989, 80354, 80719, 81084, 81450, 81815, 82180,
    82545, 82911, 83276, 83641, 84006, 84371, 84736, 85101, 85466, 85832, 86197, 86562, 86927,
    87293, 87658, 88023, 88388, 88754, 89119, 89484, 89849, 90215, 90580, 90945, 91310, 91676,
    92041, 92406, 92771, 93137, 93502, 93867, 94232, 94598, 94963, 95328, 95693, 96059, 96424,
    96789, 97154, 97520, 97885, 98250, 98615, 98981, 99346, 99711, 100076, 100442, 100807, 101172,
    101537, 101903, 102268, 102633, 102998, 103364, 103729, 104094, 104459, 104825, 105190, 105555,
    105920, 106286, 106651, 107016, 107381, 107747, 108112, 108477, 108842, 109208, 109573, 109938,
    110303, 110669, 111034, 111399, 111764, 112130, 112495, 112860, 113225, 113591, 113956, 114321,
    114686, 115052, 115417, 115782, 116147, 116513, 116878, 117243, 117608, 117974, 118339, 118704,
    119069, 119435, 119800, 120165, 120530, 120895, 121260, 121625, 121990, 122356, 122721, 123086,
    123451, 123817, 124182, 124547, 124912, 125278, 125643, 126008, 126373, 126739, 127104, 127469,
    127834, 128200, 128565, 128930, 129295, 129661, 130026, 130391, 130756, 131122, 131487, 131852,
    132217, 132583, 132948, 133313, 133678, 134044, 134409, 134774, 135139, 135505, 135870, 136235,
    136600, 136966, 137331, 137696, 138061, 138427, 138792, 139157, 139522, 139888, 140253, 140618,
    140983, 141349, 141714, 142079, 142444, 142810, 143175, 143540, 143905, 144271, 144636, 145001,
    145366, 145732,
];

#[cfg_attr(any(test, feature = "derive-debug"), derive(Debug))]
pub enum TimeError {
    InvalidTimestamp,
    BufferTooSmall,
}

impl From<CapacityError> for TimeError {
    fn from(_: CapacityError) -> Self {
        TimeError::BufferTooSmall
    }
}

// this is used to add a leading 0
// to a single digit number, to "emulate"
// format!("{:0>2}", 1); which returns 01
// this is used to format month, days, hours, minutes
// and seconds when formatting timestamps.
macro_rules! add_padding {
    ($num:expr, $string:expr) => {
        if $num < 10 {
            $string.push(b'0');
        }
    };
}

#[derive(Debug)]
pub struct Date {
    day: u8,
    month: u8,
    year: u32,
    hour: u8,
    min: u8,
    sec: u8,
}

/// Conversts a unix `timestamp`
/// returns a date
pub fn timestamp_to_date(timestamp: i64) -> Result<Date, TimeError> {
    let month_days = PIC::new(MONTH_DAYS).into_inner();
    let year_lookup = PIC::new(YEAR_LOOKUP).into_inner();

    let mut t = timestamp;
    let mut tm_day: u16;

    let tm_sec = (t % 60) as u8;
    t -= tm_sec as i64;
    t /= 60;

    let tm_min = (t % 60) as u8;
    t -= tm_min as i64;
    t /= 60;

    let tm_hour = (t % 24) as u8;
    t -= tm_hour as i64;
    t /= 24;

    // Look up tm_year
    let mut tm_year = 0;

    while tm_year < year_lookup.len() && year_lookup[tm_year] <= t as _ {
        tm_year += 1;
    }

    if tm_year == 0 || tm_year == year_lookup.len() {
        return Err(TimeError::InvalidTimestamp);
    }
    tm_year -= 1;

    tm_day = (t as u32 - year_lookup[tm_year] + 1) as u16;
    tm_year += 1970;

    // Get day/month
    let leap = ((tm_year % 4 == 0) && (tm_year % 100 != 0 || tm_year % 400 == 0)) as u8;

    let mut tm_mon = 0;
    for i in 0..12 {
        tm_mon = i;
        let mut tmp = month_days[tm_mon];
        tmp += if tm_mon == 1 { leap } else { 0 };

        if tm_day <= tmp as _ {
            break;
        }
        tm_day -= tmp as u16;
    }
    tm_mon += 1;

    Ok(Date {
        day: tm_day as u8,
        month: tm_mon as _,
        year: tm_year as _,
        hour: tm_hour,
        min: tm_min,
        sec: tm_sec,
    })
}

/// Conversts a unix `timestamp`
/// returns a formatted date string  on success
pub fn timestamp_to_str_date(
    timestamp: i64,
) -> Result<ArrayVec<u8, FORMATTED_STR_DATE_LEN>, TimeError> {
    let date = timestamp_to_date(timestamp)?;

    let mut date_str = ArrayVec::<_, FORMATTED_STR_DATE_LEN>::new();
    let mut num_buff = [0; u64::FORMATTED_SIZE_DECIMAL + 2];

    // separators
    let dash = b'-';
    let space = b' ';
    let colon = b':';
    let utc = pic_str!(b"UTC"!);

    // year, does not require adding leading
    // zeroes
    let num =
        u64_to_str(date.year as _, &mut num_buff[..]).map_err(|_| TimeError::BufferTooSmall)?;
    date_str.try_extend_from_slice(num)?;
    date_str.push(dash);
    // month
    add_padding!(date.month, date_str);
    let num =
        u8_to_str(date.month as _, &mut num_buff[..]).map_err(|_| TimeError::BufferTooSmall)?;
    date_str.try_extend_from_slice(num)?;
    date_str.push(dash);
    // day
    add_padding!(date.day, date_str);
    let num = u8_to_str(date.day, &mut num_buff[..]).map_err(|_| TimeError::BufferTooSmall)?;
    date_str.try_extend_from_slice(num)?;
    date_str.push(space);

    // time
    // hour
    add_padding!(date.hour, date_str);
    let num = u8_to_str(date.hour, &mut num_buff[..]).map_err(|_| TimeError::BufferTooSmall)?;
    date_str.try_extend_from_slice(num)?;
    date_str.push(colon);
    // min
    add_padding!(date.min, date_str);
    let num = u8_to_str(date.min, &mut num_buff[..]).map_err(|_| TimeError::BufferTooSmall)?;
    date_str.try_extend_from_slice(num)?;
    date_str.push(colon);
    // seconds
    add_padding!(date.sec, date_str);
    let num = u8_to_str(date.sec, &mut num_buff[..]).map_err(|_| TimeError::BufferTooSmall)?;
    date_str.try_extend_from_slice(num)?;
    date_str.push(space);

    // it is redundant to have Utc appended at the end
    // as by definition unix-timestamp is Utc, but this
    // keeps compatibility with legacy app
    date_str.try_extend_from_slice(&utc[..])?;

    Ok(date_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_to_str() {
        use time::format_description;
        use time::OffsetDateTime;

        let timestamp = [1657089945, 55471502, 1663087639];

        for t in timestamp {
            let date = OffsetDateTime::from_unix_timestamp(t).unwrap();
            let format =
                format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC")
                    .unwrap();

            let date_str = date.format(&format).unwrap();

            let test_date = timestamp_to_str_date(t).unwrap();
            let test_date = std::str::from_utf8(test_date.as_slice()).unwrap();

            assert_eq!(&date_str, test_date);
        }
    }
}
