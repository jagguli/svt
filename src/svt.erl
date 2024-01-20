%%% @doc
%%% References:
%%% 1. API (plain text) encoding of AE values: https://github.com/aeternity/protocol/blob/fd179822fc70241e79cbef7636625cf344a08109/node/api/api_encoding.md
%%% 2. AE Serializations: https://github.com/aeternity/protocol/blob/fd179822fc70241e79cbef7636625cf344a08109/serializations.md
%%% 3. RLP: https://zxq9.com/archives/2749
%%% 4. BaseN:
%%% @end

-module(svt).
-export([start/1]).

-define(TAG_CONTRACT_CALL_TX, 43).
-define(TAG_SIGNED_TX, 11).
-define(OBJECT_VERSION, 1).


-spec start(ArgV) -> ok
    when ArgV :: [string()].

start(ArgV) ->
    ok = main(ArgV),
    zx:silent_stop().


unsigned_tx_data() ->
    "tx_+LUrAaEBzZdh1MDoqUeB7A/dvSoARg6L/nLK94Po8YYSBwtGkhMBoQWPFvtl5SACr++edEMrwJzoQp7/Tu6vJ3vxsdi9P5O+hQOGteYg9IAAAACCTiCEO5rKALhaKxH1lAXbW58AoM2XYdTA6KlHgewP3b0qAEYOi/5yyveD6PGGEgcLRpITAJ8AoM2XYdTA6KlHgewP3b0qAEYOi/5yyveD6PGGEgcLRpITOG+JA72RPmwd8//AoZ9UjA==".
private_key() ->
    "59dee4218cc7d090b90ff15bd65f6fa8858a625d93861ca2ee77d63fd30be7d029f0a54388d542910640181cf00c9932e8870cb6e155581c6f69c725225c304f".
%% first task is to decompose that

main([]) ->
    %% get the actual bytes out of the tx_... garbage
    "tx_" ++ Base64Data                 = unsigned_tx_data(),
    CheckedData                         = base64:decode(Base64Data),
    %% check the check digits
    ActualDataSize                      = byte_size(CheckedData) - 4,
    <<ActualData:ActualDataSize/bytes,
      CheckBytes:4/bytes>>              = CheckedData,
    true                                = check_bytes_match(ActualData, CheckBytes),
    %% unRLPencode (i guess the word is decode) the raw bytes
    {Tx, <<>>} = vrlp:decode(ActualData),
    io:format("Mansplain Unsigned data: ~tp~n", [mansplain(Tx)]),
    Signature = crypto:sign(ecdsa, sha, Tx, private_key(),[]),
    SignedContractCallTxRaw = vrlp:encode([
        encode_int(?TAG_SIGNED_TX),
        encode_int(?OBJECT_VERSION),
        Signature,
        unsigned_tx_data()
    ]),
    CheckBytes0 = shasha4(SignedContractCallTxRaw),
    io:format("Mainsplain Signed data: ~tp~n", [mansplain(SignedContractCallTxRaw)]),
    CheckedData0 = <<SignedContractCallTxRaw/bytes, CheckBytes0:4/bytes>>,
    Base64Data0 = base64:encode(CheckedData0),
    SignedContractCall = "tx_" ++ Base64Data0,
    io:format("Signed contract call: ~tp~n", [SignedContractCall]).



check_bytes_match(ActualData, CheckBytes) ->
    CheckBytes =:= shasha4(ActualData).

shasha4(Bytes) ->
    <<CheckBytes:4/bytes, _/bytes>> = crypto:hash(sha256, crypto:hash(sha256, Bytes)),
    CheckBytes.


%% The idea of mansplaining
%% is displaying computer nonsense in a way that is human readable

%% Take the RLP representation of an AE object and return a data structure that
%% a human can read
mansplain([TagBytes, VsnBytes | Fields]) ->
    TagInt = decode_int(TagBytes),
    VsnInt = decode_int(VsnBytes),
    mansplain(TagInt, VsnInt, Fields).


mansplain(?TAG_SIGNED_TX, ?OBJECT_VERSION, Fields) ->
    [Signatures_bytes,   %% [ <signatures>      :: binary()
     Transaction_bytes]  %% , <transaction>       :: binary()
        = Fields,
    #{signatures  => mansplain_id(Signatures_bytes),
      transaction => mansplain_int(Transaction_bytes)};
    

%% Contract call tx
mansplain(?TAG_CONTRACT_CALL_TX, 1, Fields) ->
    %% Ref: https://github.com/aeternity/protocol/blob/fd179822fc70241e79cbef7636625cf344a08109/serializations.md#contract-call-transaction
    [CallerId_bytes,   %% [ <caller>      :: id()
     Nonce_bytes,      %% , <nonce>       :: int()
     ContractId_bytes, %% , <contract>    :: id()
     ABIVersion_bytes, %% , <abi_version> :: int()
     Fee_bytes,        %% , <fee>         :: int()
     TTL_bytes,        %% , <ttl>         :: int()
     Amount_bytes,     %% , <amount>      :: int()
     Gas_bytes,        %% , <gas>         :: int()
     GasPrice_bytes,   %% , <gas_price>   :: int()
     CallData_bytes]   %% , <call_data>   :: binary()
        = Fields,
    #{caller      => mansplain_id(CallerId_bytes),
      nonce       => mansplain_int(Nonce_bytes),
      contract    => mansplain_id(ContractId_bytes),
      abi_version => mansplain_int(ABIVersion_bytes),
      fee         => mansplain_int(Fee_bytes),
      ttl         => mansplain_int(TTL_bytes),
      amount      => mansplain_int(Amount_bytes),
      gas         => mansplain_int(Gas_bytes),
      gas_price   => mansplain_int(GasPrice_bytes),
      call_data   => CallData_bytes}.


%% mansplain an id = show the ak_... nonsense
%% Ref: https://github.com/aeternity/protocol/blob/fd179822fc70241e79cbef7636625cf344a08109/serializations.md#the-id-type
mansplain_id(<<Tag, IdBytes:32/bytes>>) ->
    PrefixStr = prefix(Tag),
    IdStr     = base58checked(IdBytes),
    PrefixStr ++ "_" ++ IdStr.


%% Ref: https://github.com/aeternity/protocol/blob/fd179822fc70241e79cbef7636625cf344a08109/serializations.md#the-id-type
prefix(1) -> "ak";
prefix(2) -> "nm";
prefix(3) -> "cm";
prefix(4) -> "ok";
prefix(5) -> "ct";
prefix(6) -> "ch".


%% Add the check bytes and base58-encode a bytestring
base58checked(Bytes) ->
    %% add check bytes
    vb58:enc(add_check_bytes(Bytes)).

add_check_bytes(Bytes) ->
    CheckBytes = shasha4(Bytes),
    <<Bytes/bytes, CheckBytes/bytes>>.


%% mansplain an integer = show the integer
mansplain_int(IntBytes) ->
    decode_int(IntBytes).


%% Decode functions

%% Take a bytestring and parse it as an int
decode_int(Bytes) ->
    binary:decode_unsigned(Bytes).
encode_int(Int) ->
    binary:encode_unsigned(Int).


