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

//network ids
pub const NETWORK_ID_MAINNET: u32 = 1;
pub const NETWORK_ID_FUJI: u32 = 5;
pub const NETWORK_ID_LOCAL: u32 = 12345;

// hrp
pub const HRP_MAINNET: &str = "avax";
pub const HRP_TESTNET: &str = "fuji";
pub const HRP_LOCAL: &str = "local";

pub const TRANSFER_TX: u32 = 0;

// pvm transaction types
pub const PVM_CREATE_SUBNET: u32 = 0x00000010;
pub const PVM_EXPORT_TX: u32 = 0x00000012;
pub const PVM_IMPORT_TX: u32 = 0x00000011;
pub const PVM_ADD_VALIDATOR: u32 = 0x0000000c;
pub const PVM_ADD_SUBNET_VALIDATOR: u32 = 0x0000000d;
pub const PVM_ADD_DELEGATOR: u32 = 0x0000000e;
pub const PVM_CREATE_CHAIN: u32 = 0x0000000f;

// avm transaction types
pub const AVM_CREATE_ASSET_TX: u32 = 0x00000001;
pub const AVM_OPERATION_TX: u32 = 0x00000002;
pub const AVM_IMPORT_TX: u32 = 0x00000003;
pub const AVM_EXPORT_TX: u32 = 0x00000004;

// evm transaction types
pub const EVM_IMPORT_TX: u32 = 0x00000000;
pub const EVM_EXPORT_TX: u32 = 0x00000001;

//Avax units
pub const NANO_AVAX_DECIMAL_DIGITS: usize = 9;
pub const WEI_NAVAX_DIGITS: usize = 9;
pub const WEI_AVAX_DIGITS: usize = 18;
pub const DELEGATION_FEE_DIGITS: usize = 4;

// data formatting constants

// the lenght required to format a date like:
// yyyy-mm-dd hh:mm:ss UTC
pub const FORMATTED_STR_DATE_LEN: usize = 23;

// other constants
pub const CB58_CHECKSUM_LEN: usize = 4;
pub const U32_SIZE: usize = std::mem::size_of::<u32>();

// types
pub type OutputIdx = u32;
