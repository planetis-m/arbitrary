import arbitrary/unstructured

export unstructured

proc sample*[T](x: var Unstructured; a: openArray[T]): T {.inline.} =
  assert(a.len > 0, "The array must be non empty.")
  result = a[intInRange(x, a.low, a.high)]

proc ratio*[T](x: var Unstructured; numerator, denominator: T): bool =
  assert(0 < numerator)
  assert(numerator <= denominator)
  let x = intInRange(x, 1, denominator)
  result = x <= numerator

template implForInts(ty, unsigned) =
  proc arbitrary*(x: var Unstructured; result: var ty) =
    var res: unsigned = 0
    for i in 0..<sizeof(ty):
      res = res or unsigned(x.data[i]) shl (i * 8)
    advance(x, sizeof(ty))
    result = cast[ty](res)

#implForInts(int16, uint16)

proc read*[T: SomeNumber](x: var Unstructured): T =
  result = 0
  x.readData(addr result, sizeof(result))

template sizeHint*(t: typedesc[int64]): (int, int) =
  (sizeof(t), sizeof(t))

proc restLen*[T](x: var Unstructured): int =
  let byteSize = x.byteSize
  let (lower, upper) = sizeHint(T)
  let elemSize = max(1, if upper > -1: upper else: lower * 2)
  result = byteSize div elemSize

