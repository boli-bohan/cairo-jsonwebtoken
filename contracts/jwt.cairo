%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.memcpy import memcpy

from contracts.Str import Str, str_concat, str_concat_literal, str_empty
from contracts.lib.base64 import base64_encode, base64_decode

#
# Takes json formatted header/payload + secret and generate JWT string
# Returns empty string on failure
#
func encode{range_check_ptr}(header : Str, payload : Str, secret : Str) -> (jwt : Str):
    alloc_locals

    let res = _validate_header(header)
    if res == 0:
        return (str_empty())
    
    let res = _validate_payload(payload)
    if res == 0:
        return (str_empty())

    let header_part = base64_encode_str(header)
    let payload_part = base64_encode_str(payload)
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
    if _validate_simple_json(header) == 0:
        return (0)

    if _validate_json_field_exists(header, 'alg') == 0:
        return (0)

    if _validate_json_field_exists(header, 'kid') == 0:
        return (0)

    return (1)
end

#
# check valid json + fields, return 0 if invalid
#
func _validate_payload{range_check_ptr}(payload : Str) -> (res : felt) :
    if _validate_simple_json(payload) == 0:
        return (0)

    return (1)
end

#
# check if string is a simple json (no nested objects/arrays), return 0 if invalid
#
func _validate_simple_json{range_check_ptr}(in : Str) -> (res : felt) :
end

#
# check if field is present in string
#
func _validate_json_field_exists{range_check_ptr}(in : Str, literal : felt) -> (res : felt) :    
end

#
# perform HMACSHA256 hash on data + secret
#
func _hs256{range_check_ptr}(data : Str, secret : Str) -> (output : Str) :
    # TODO: wait for sha256 builtin

    # The algorithm requires the key to be of the same length as the
    # "block-size" of the hashing algorithm (SHA256 = 64-byte blocks).
    # Extension is performed by appending zeros.
    # var fullLengthKey = extendOrTruncateKey(key);
    # 
    # var outterKeyPad = 0x5c; // A constant defined by the spec.
    # var innerKeyPad = 0x36; // Another constant defined by the spec.
    # 
    # var outterKey = new Buffer(fullLengthKey.length);
    # var innerKey = new Buffer(fullLengthKey.length);
    # for(var i = 0; i < fullLengthKey.length; ++i) {
        # outterKey[i] = outterKeyPad ^ fullLengthKey[i];
        # innerKey[i] = innerKeyPad ^ fullLengthKey[i];
    # }
    # 
    # // sha256(outterKey + sha256(innerKey, message))
    # // (Buffer.concat makes this harder to read)
    # return sha256(Buffer.concat([outterKey, sha256(Buffer.concat([innerKey, message]))]));
    
    return (str_empty())
end