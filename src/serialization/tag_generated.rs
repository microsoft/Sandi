// automatically generated by the FlatBuffers compiler, do not modify


// @generated

use crate::common_generated::*;
use core::mem;
use core::cmp::Ordering;

extern crate flatbuffers;
use self::flatbuffers::{EndianScalar, Follow};

#[allow(unused_imports, dead_code)]
pub mod reputation {

  use crate::common_generated::*;
  use core::mem;
  use core::cmp::Ordering;

  extern crate flatbuffers;
  use self::flatbuffers::{EndianScalar, Follow};
#[allow(unused_imports, dead_code)]
pub mod fbs {

  use crate::common_generated::*;
  use core::mem;
  use core::cmp::Ordering;

  extern crate flatbuffers;
  use self::flatbuffers::{EndianScalar, Follow};

pub enum TagOffset {}
#[derive(Copy, Clone, PartialEq)]

pub struct Tag<'a> {
  pub _tab: flatbuffers::Table<'a>,
}

impl<'a> flatbuffers::Follow<'a> for Tag<'a> {
  type Inner = Tag<'a>;
  #[inline]
  unsafe fn follow(buf: &'a [u8], loc: usize) -> Self::Inner {
    Self { _tab: flatbuffers::Table::new(buf, loc) }
  }
}

impl<'a> Tag<'a> {
  pub const VT_COMMITMENT: flatbuffers::VOffsetT = 4;
  pub const VT_EXPIRATION: flatbuffers::VOffsetT = 6;
  pub const VT_SCORE: flatbuffers::VOffsetT = 8;
  pub const VT_ENC_SENDER_ID: flatbuffers::VOffsetT = 10;
  pub const VT_Q_BIG: flatbuffers::VOffsetT = 12;
  pub const VT_G_PRIME: flatbuffers::VOffsetT = 14;
  pub const VT_X_BIG: flatbuffers::VOffsetT = 16;
  pub const VT_SIGNATURE: flatbuffers::VOffsetT = 18;

  #[inline]
  pub unsafe fn init_from_table(table: flatbuffers::Table<'a>) -> Self {
    Tag { _tab: table }
  }
  #[allow(unused_mut)]
  pub fn create<'bldr: 'args, 'args: 'mut_bldr, 'mut_bldr>(
    _fbb: &'mut_bldr mut flatbuffers::FlatBufferBuilder<'bldr>,
    args: &'args TagArgs<'args>
  ) -> flatbuffers::WIPOffset<Tag<'bldr>> {
    let mut builder = TagBuilder::new(_fbb);
    builder.add_expiration(args.expiration);
    if let Some(x) = args.signature { builder.add_signature(x); }
    if let Some(x) = args.x_big { builder.add_x_big(x); }
    if let Some(x) = args.g_prime { builder.add_g_prime(x); }
    if let Some(x) = args.q_big { builder.add_q_big(x); }
    if let Some(x) = args.enc_sender_id { builder.add_enc_sender_id(x); }
    builder.add_score(args.score);
    if let Some(x) = args.commitment { builder.add_commitment(x); }
    builder.finish()
  }


  #[inline]
  pub fn commitment(&self) -> &'a FixedBuffer32 {
    // Safety:
    // Created from valid Table for this object
    // which contains a valid value in this slot
    unsafe { self._tab.get::<FixedBuffer32>(Tag::VT_COMMITMENT, None).unwrap()}
  }
  #[inline]
  pub fn expiration(&self) -> i64 {
    // Safety:
    // Created from valid Table for this object
    // which contains a valid value in this slot
    unsafe { self._tab.get::<i64>(Tag::VT_EXPIRATION, Some(0)).unwrap()}
  }
  #[inline]
  pub fn score(&self) -> i32 {
    // Safety:
    // Created from valid Table for this object
    // which contains a valid value in this slot
    unsafe { self._tab.get::<i32>(Tag::VT_SCORE, Some(0)).unwrap()}
  }
  #[inline]
  pub fn enc_sender_id(&self) -> &'a FixedBuffer16 {
    // Safety:
    // Created from valid Table for this object
    // which contains a valid value in this slot
    unsafe { self._tab.get::<FixedBuffer16>(Tag::VT_ENC_SENDER_ID, None).unwrap()}
  }
  #[inline]
  pub fn q_big(&self) -> &'a FixedBuffer32 {
    // Safety:
    // Created from valid Table for this object
    // which contains a valid value in this slot
    unsafe { self._tab.get::<FixedBuffer32>(Tag::VT_Q_BIG, None).unwrap()}
  }
  #[inline]
  pub fn g_prime(&self) -> &'a FixedBuffer32 {
    // Safety:
    // Created from valid Table for this object
    // which contains a valid value in this slot
    unsafe { self._tab.get::<FixedBuffer32>(Tag::VT_G_PRIME, None).unwrap()}
  }
  #[inline]
  pub fn x_big(&self) -> &'a FixedBuffer32 {
    // Safety:
    // Created from valid Table for this object
    // which contains a valid value in this slot
    unsafe { self._tab.get::<FixedBuffer32>(Tag::VT_X_BIG, None).unwrap()}
  }
  #[inline]
  pub fn signature(&self) -> &'a FixedBuffer64 {
    // Safety:
    // Created from valid Table for this object
    // which contains a valid value in this slot
    unsafe { self._tab.get::<FixedBuffer64>(Tag::VT_SIGNATURE, None).unwrap()}
  }
}

impl flatbuffers::Verifiable for Tag<'_> {
  #[inline]
  fn run_verifier(
    v: &mut flatbuffers::Verifier, pos: usize
  ) -> Result<(), flatbuffers::InvalidFlatbuffer> {
    use self::flatbuffers::Verifiable;
    v.visit_table(pos)?
     .visit_field::<FixedBuffer32>("commitment", Self::VT_COMMITMENT, true)?
     .visit_field::<i64>("expiration", Self::VT_EXPIRATION, false)?
     .visit_field::<i32>("score", Self::VT_SCORE, false)?
     .visit_field::<FixedBuffer16>("enc_sender_id", Self::VT_ENC_SENDER_ID, true)?
     .visit_field::<FixedBuffer32>("q_big", Self::VT_Q_BIG, true)?
     .visit_field::<FixedBuffer32>("g_prime", Self::VT_G_PRIME, true)?
     .visit_field::<FixedBuffer32>("x_big", Self::VT_X_BIG, true)?
     .visit_field::<FixedBuffer64>("signature", Self::VT_SIGNATURE, true)?
     .finish();
    Ok(())
  }
}
pub struct TagArgs<'a> {
    pub commitment: Option<&'a FixedBuffer32>,
    pub expiration: i64,
    pub score: i32,
    pub enc_sender_id: Option<&'a FixedBuffer16>,
    pub q_big: Option<&'a FixedBuffer32>,
    pub g_prime: Option<&'a FixedBuffer32>,
    pub x_big: Option<&'a FixedBuffer32>,
    pub signature: Option<&'a FixedBuffer64>,
}
impl<'a> Default for TagArgs<'a> {
  #[inline]
  fn default() -> Self {
    TagArgs {
      commitment: None, // required field
      expiration: 0,
      score: 0,
      enc_sender_id: None, // required field
      q_big: None, // required field
      g_prime: None, // required field
      x_big: None, // required field
      signature: None, // required field
    }
  }
}

pub struct TagBuilder<'a: 'b, 'b> {
  fbb_: &'b mut flatbuffers::FlatBufferBuilder<'a>,
  start_: flatbuffers::WIPOffset<flatbuffers::TableUnfinishedWIPOffset>,
}
impl<'a: 'b, 'b> TagBuilder<'a, 'b> {
  #[inline]
  pub fn add_commitment(&mut self, commitment: &FixedBuffer32) {
    self.fbb_.push_slot_always::<&FixedBuffer32>(Tag::VT_COMMITMENT, commitment);
  }
  #[inline]
  pub fn add_expiration(&mut self, expiration: i64) {
    self.fbb_.push_slot::<i64>(Tag::VT_EXPIRATION, expiration, 0);
  }
  #[inline]
  pub fn add_score(&mut self, score: i32) {
    self.fbb_.push_slot::<i32>(Tag::VT_SCORE, score, 0);
  }
  #[inline]
  pub fn add_enc_sender_id(&mut self, enc_sender_id: &FixedBuffer16) {
    self.fbb_.push_slot_always::<&FixedBuffer16>(Tag::VT_ENC_SENDER_ID, enc_sender_id);
  }
  #[inline]
  pub fn add_q_big(&mut self, q_big: &FixedBuffer32) {
    self.fbb_.push_slot_always::<&FixedBuffer32>(Tag::VT_Q_BIG, q_big);
  }
  #[inline]
  pub fn add_g_prime(&mut self, g_prime: &FixedBuffer32) {
    self.fbb_.push_slot_always::<&FixedBuffer32>(Tag::VT_G_PRIME, g_prime);
  }
  #[inline]
  pub fn add_x_big(&mut self, x_big: &FixedBuffer32) {
    self.fbb_.push_slot_always::<&FixedBuffer32>(Tag::VT_X_BIG, x_big);
  }
  #[inline]
  pub fn add_signature(&mut self, signature: &FixedBuffer64) {
    self.fbb_.push_slot_always::<&FixedBuffer64>(Tag::VT_SIGNATURE, signature);
  }
  #[inline]
  pub fn new(_fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>) -> TagBuilder<'a, 'b> {
    let start = _fbb.start_table();
    TagBuilder {
      fbb_: _fbb,
      start_: start,
    }
  }
  #[inline]
  pub fn finish(self) -> flatbuffers::WIPOffset<Tag<'a>> {
    let o = self.fbb_.end_table(self.start_);
    self.fbb_.required(o, Tag::VT_COMMITMENT,"commitment");
    self.fbb_.required(o, Tag::VT_ENC_SENDER_ID,"enc_sender_id");
    self.fbb_.required(o, Tag::VT_Q_BIG,"q_big");
    self.fbb_.required(o, Tag::VT_G_PRIME,"g_prime");
    self.fbb_.required(o, Tag::VT_X_BIG,"x_big");
    self.fbb_.required(o, Tag::VT_SIGNATURE,"signature");
    flatbuffers::WIPOffset::new(o.value())
  }
}

impl core::fmt::Debug for Tag<'_> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    let mut ds = f.debug_struct("Tag");
      ds.field("commitment", &self.commitment());
      ds.field("expiration", &self.expiration());
      ds.field("score", &self.score());
      ds.field("enc_sender_id", &self.enc_sender_id());
      ds.field("q_big", &self.q_big());
      ds.field("g_prime", &self.g_prime());
      ds.field("x_big", &self.x_big());
      ds.field("signature", &self.signature());
      ds.finish()
  }
}
#[inline]
/// Verifies that a buffer of bytes contains a `Tag`
/// and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_tag_unchecked`.
pub fn root_as_tag(buf: &[u8]) -> Result<Tag, flatbuffers::InvalidFlatbuffer> {
  flatbuffers::root::<Tag>(buf)
}
#[inline]
/// Verifies that a buffer of bytes contains a size prefixed
/// `Tag` and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `size_prefixed_root_as_tag_unchecked`.
pub fn size_prefixed_root_as_tag(buf: &[u8]) -> Result<Tag, flatbuffers::InvalidFlatbuffer> {
  flatbuffers::size_prefixed_root::<Tag>(buf)
}
#[inline]
/// Verifies, with the given options, that a buffer of bytes
/// contains a `Tag` and returns it.
/// Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_tag_unchecked`.
pub fn root_as_tag_with_opts<'b, 'o>(
  opts: &'o flatbuffers::VerifierOptions,
  buf: &'b [u8],
) -> Result<Tag<'b>, flatbuffers::InvalidFlatbuffer> {
  flatbuffers::root_with_opts::<Tag<'b>>(opts, buf)
}
#[inline]
/// Verifies, with the given verifier options, that a buffer of
/// bytes contains a size prefixed `Tag` and returns
/// it. Note that verification is still experimental and may not
/// catch every error, or be maximally performant. For the
/// previous, unchecked, behavior use
/// `root_as_tag_unchecked`.
pub fn size_prefixed_root_as_tag_with_opts<'b, 'o>(
  opts: &'o flatbuffers::VerifierOptions,
  buf: &'b [u8],
) -> Result<Tag<'b>, flatbuffers::InvalidFlatbuffer> {
  flatbuffers::size_prefixed_root_with_opts::<Tag<'b>>(opts, buf)
}
#[inline]
/// Assumes, without verification, that a buffer of bytes contains a Tag and returns it.
/// # Safety
/// Callers must trust the given bytes do indeed contain a valid `Tag`.
pub unsafe fn root_as_tag_unchecked(buf: &[u8]) -> Tag {
  flatbuffers::root_unchecked::<Tag>(buf)
}
#[inline]
/// Assumes, without verification, that a buffer of bytes contains a size prefixed Tag and returns it.
/// # Safety
/// Callers must trust the given bytes do indeed contain a valid size prefixed `Tag`.
pub unsafe fn size_prefixed_root_as_tag_unchecked(buf: &[u8]) -> Tag {
  flatbuffers::size_prefixed_root_unchecked::<Tag>(buf)
}
#[inline]
pub fn finish_tag_buffer<'a, 'b>(
    fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>,
    root: flatbuffers::WIPOffset<Tag<'a>>) {
  fbb.finish(root, None);
}

#[inline]
pub fn finish_size_prefixed_tag_buffer<'a, 'b>(fbb: &'b mut flatbuffers::FlatBufferBuilder<'a>, root: flatbuffers::WIPOffset<Tag<'a>>) {
  fbb.finish_size_prefixed(root, None);
}
}  // pub mod fbs
}  // pub mod reputation

