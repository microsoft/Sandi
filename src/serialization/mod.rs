// This is a modified version of the generated mod.rs
// We use it because it fixes a lot of namespace issues with the generated code.

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
