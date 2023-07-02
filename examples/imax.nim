import ".."/arbitrary

proc twoMax1(x: openarray[int8]): (int8, int8) =
  var
    max1 = x[0]
    max2 = x[1]
  for i in 1..<x.len:
    let xi = x[i]
    if xi > max1:
      max2 = max1
      max1 = xi
    elif xi > max2:
      max2 = xi
  result = (max1, max2)

proc twoMax2(x: openarray[int8]): (int8, int8) =
  var
    max1 = x[0]
    max2 = x[1]
  if max2 > max1:
    swap(max1, max2)
  for i in 2..<x.len:
    let xi = x[i]
    if xi > max1:
      max2 = max1
      max1 = xi
    elif xi > max2:
      max2 = xi
  result = (max1, max2)

proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
    exportc: "LLVMFuzzerTestOneInput", raises: [].} =
  var x = toUnstructured(data, len)
  let len = x.byteSize div sizeof(int8)
  if len < 2: return
  var copy = newSeq[int8](len)
  for i in 0..<len:
    copy[i] = x.readInt[:int8]
  let res = twoMax1(copy)
  doAssert res == twoMax2(copy)

when defined(fuzzSa):
  include libfuzzer/standalone
else:
  proc initialize(): cint {.exportc: "LLVMFuzzerInitialize".} =
    {.emit: "N_CDECL(void, NimMain)(void); NimMain();".}
