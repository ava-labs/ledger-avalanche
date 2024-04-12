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

pub trait ApduPanic: Sized {
    type Item;

    fn apdu_unwrap(self) -> Self::Item;

    fn apdu_expect(self, s: &str) -> Self::Item;
}

impl<T, E> ApduPanic for Result<T, E> {
    type Item = T;

    #[inline]
    fn apdu_unwrap(self) -> Self::Item {
        match self {
            Ok(t) => t,
            Err(_) => panic!(),
        }
    }

    #[inline]
    fn apdu_expect(self, _: &str) -> Self::Item {
        match self {
            Ok(t) => t,
            Err(_) => panic!(),
        }
    }
}

impl<T> ApduPanic for Option<T> {
    type Item = T;

    #[inline]
    fn apdu_unwrap(self) -> Self::Item {
        match self {
            Some(t) => t,
            None => panic!(),
        }
    }

    #[inline]
    fn apdu_expect(self, _: &str) -> Self::Item {
        match self {
            Some(t) => t,
            None => panic!(),
        }
    }
}
