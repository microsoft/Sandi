// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// This will turn off warnings for the generated code, since we have little
// control over it.
#![allow(warnings)]
mod fixed_buffer_32_generated;
pub use self::fixed_buffer_32_generated::*;
mod fixed_buffer_48_generated;
pub use self::fixed_buffer_48_generated::*;
mod fixed_buffer_64_generated;
pub use self::fixed_buffer_64_generated::*;
mod tag_generated;
pub use self::tag_generated::*;
mod full_tag_generated;
pub use self::full_tag_generated::*;
