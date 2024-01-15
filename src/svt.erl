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
    "privkey".
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
    {RLPData, <<>>} = vrlp:decode(ActualData),
    io:format("Unsigned data: ~tp~n", [mansplain(RLPData)]),
    Signature = sign_tx(unsigned_tx_data(), private_key()),
    RLPData0 = vrlp:encode([
        encode_int(?TAG_SIGNED_TX),
        encode_int(?OBJECT_VERSION),
        Signature,
        unsigned_tx_data()
    ]),
    io:format("Signed data: ~tp~n", [mansplain(RLPData0)]),
    ok.


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


-define(VALID_PRIVK(K), byte_size(K) =:= 64).
sign_tx(Tx, PrivKey) -> sign_tx(Tx, PrivKey, false).
sign_tx(Tx, PrivKey, SignHash) -> sign_tx(Tx, PrivKey, SignHash, undefined).
sign_tx(Tx, PrivKey, SignHash, Pfx) ->
  %% set debug true to meet legacy expectations (?)
  sign_tx(Tx, PrivKey, SignHash, Pfx, [{debug, true}]).


sign_tx(Tx, PrivKey, SignHash, AdditionalPrefix, Cfg) when is_binary(PrivKey) ->
  sign_tx(Tx, [PrivKey], SignHash, AdditionalPrefix, Cfg);

sign_tx(Tx, PrivKeys, SignHash, AdditionalPrefix, _Cfg) when is_list(PrivKeys) ->
  Bin0 = aetx:serialize_to_binary(Tx),
  Bin1 =
    case SignHash of
      true -> aec_hash:hash(signed_tx, Bin0);
      false -> Bin0
    end,
  Bin =
    case AdditionalPrefix of
      undefined -> Bin1;
      _ -> <<"-", AdditionalPrefix/binary, Bin1/binary>>
    end,
  BinForNetwork = aec_governance:add_network_id(Bin),
  case lists:filter(fun (PrivKey) -> not (?VALID_PRIVK(PrivKey)) end, PrivKeys) of
    [_ | _] = BrokenKeys -> erlang:error({invalid_priv_key, BrokenKeys});
    [] -> pass
  end,
  Signatures =
    [enacl:sign_detached(BinForNetwork, PrivKey) || PrivKey <- PrivKeys],
  aetx_sign:new(Tx, Signatures).
