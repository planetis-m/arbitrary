type
  Unstructured* = object
    data: ptr UncheckedArray[byte]
    remainingBytes: int

template `+!`(p: pointer, s: int): untyped =
  cast[pointer](cast[ByteAddress](p) +% s)

template inc(p: pointer, s: int) =
  p = cast[typeof(p)](cast[ByteAddress](p) +% s)

proc toUnstructured*(data: ptr UncheckedArray[byte]; len: int): Unstructured =
  Unstructured(data: data, remainingBytes: len)

proc toUnstructured*(data: openarray[int8 | uint8]): Unstructured =
  Unstructured(data: cast[ptr UncheckedArray[byte]](data), remainingBytes: data.len)

proc remainingBytes*(x: Unstructured): int {.inline.} =
  result = x.remainingBytes

proc advance(x: var Unstructured; numBytes: int) =
  assert(numBytes <= x.remainingBytes) # Not enough data
  inc x.data, numBytes
  dec x.remainingBytes, numBytes

proc intInRange*[T: SomeInteger](x: var Unstructured; min, max: T): T =
  assert(min <= max, "intInRange requires a non-empty range")
  # When there is only one possible choice, don't waste any entropy from
  # the underlying data.
  if min == max:
    return min
  let L = max.BiggestUInt - min.BiggestUInt
  var res: BiggestUInt = 0
  var offset = 0
  while offset < sizeof(T) * 8 and (L shr offset) > 0 and
      x.remainingBytes != 0:
    # Pull bytes off the end of the seed data.
    dec x.remainingBytes
    res = (res shl 8) or x.data[x.remainingBytes]
    inc offset, 8
  # Avoid division by 0, in case |L + 1| results in overflow.
  if L != high(typeof(L)):
    res = res mod (L + 1)
  result = cast[T](min.BiggestUInt + res)

proc readData*(x: var Unstructured; buffer: pointer; bufLen: int) =
  let n = min(bufLen, x.remainingBytes)
  if n > 0: copyMem(buffer, x.data, n)
  #if bufLen > n: zeroMem(buffer +! n, bufLen - n)
  advance(x, n)

proc readEnum*[T: enum](x: var Unstructured): T =
  assert(T is Ordinal)
  result = T(intInRange(x, ord(low(T)), ord(high(T))))

proc readInt*[T: SomeInteger](x: var Unstructured): T =
  result = intInRange(x, low(T), high(T))

proc readFloat64*(x: var Unstructured): float64 =
  result = float64(readInt[uint64](x))

proc readFloat32*(x: var Unstructured): float32 =
  result = float32(readInt[uint32](x))

proc readBool*(x: var Unstructured): bool =
  result = (1 and readInt[uint8](x)) == 1

proc readStr*(x: var Unstructured; length: int): string =
  let n = min(length, x.remainingBytes)
  result = newString(n)
  if n > 0: copyMem(cstring(result), x.data, n)
  advance(x, n)

proc readBytes*(x: var Unstructured; length: int): seq[byte] =
  let n = min(length, x.remainingBytes)
  result = newSeq[byte](n)
  if n > 0: copyMem(addr result[0], x.data, n)
  advance(x, n)

proc readRandStr*(x: var Unstructured; maxLength: int): string =
  # Reserve the anticipated capaticity to prevent several reallocations.
  result = newStringOfCap(min(maxLength, x.remainingBytes))
  var i = 0
  while i < maxLength and x.remainingBytes != 0:
    var next = cast[char](x.data[0])
    advance(x, 1)
    if next == '\\' and x.remainingBytes != 0:
      next = cast[char](x.data[0])
      advance(x, 1)
      if next != '\\':
        break
    result.add next
    inc i

proc byteSize*(x: var Unstructured): int =
  if x.remainingBytes == 0:
    result = 0
  elif x.remainingBytes == 1:
    advance(x, 1)
    result = 0
  else:
    result = if x.remainingBytes.int64 <= high(int8).int64 + 1:
      let maxSize = x.remainingBytes - 1
      int x.intInRange(0'i8, maxSize.int8)
    elif x.remainingBytes.int64 <= high(int16).int64 + 2:
      let maxSize = x.remainingBytes - 2
      int x.intInRange(0'i16, maxSize.int16)
    elif x.remainingBytes.int64 <= high(int32).int64 + 4:
      let maxSize = x.remainingBytes - 4
      int x.intInRange(0'i32, maxSize.int32)
    else:
      let maxSize = x.remainingBytes - 8
      int x.intInRange(0'i64, maxSize.int64)
