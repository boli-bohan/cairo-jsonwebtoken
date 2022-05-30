%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.memcpy import memcpy

from contracts.Str import Str, str_concat, str_concat_array, str_from_literal, str_empty
from contracts.lib.base64 import base64_encode, base64_decode

#
# Takes json formatted header/payload + secret and generate JWT string
#
func encode{range_check_ptr}(header : Str, payload : Str, secret : Str) -> (jwt : Str):
    alloc_locals

    let res = _validate_header(header)
    if res == 0:
        ret
    
    let res = _validate_payload(payload)
    if res == 0:
        ret    

    let header_part = base64_encode(header)
    let payload_part = base64_encode(payload)
    let data = str_concat(str_concat_literal(header_part, '.'), payload_part)

    let sig = _hs256(data, secret)

    let jwt = str_concat(str_concat(header_part, payload_part), sig)
    return (jwt)
end

#
# Takes jwt string, validate signature, spit out header/payload
#
func decode{range_check_ptr}(jwt : Str, secret : Str) -> (header : Str, payload : Str):
end

####################################################################
# Internal functions

#
# check valid json + fields, return 0 if invalid
#
func _validate_header{range_check_ptr}(header : Str) -> (res : felt) :
end

#
# check valid json + fields, return 0 if invalid
#
func _validate_payload{range_check_ptr}(payload : Str) -> (res : felt) :
end

#
# check if string is a simple json (no nested objects/arrays), return 0 if invalid
#
func _validate_simple_json{range_check_ptr}(in : Str) -> (res : felt) :
end

#
# perform HMACSHA256
#
func _hs256{range_check_ptr}(data : Str, secret : Str) -> (res : Str) :
end