defmodule Quic.RFC9001Test do
  use ExUnit.Case, async: true

  describe "client_initial" do
    setup do
      protected_packet =
        """
        c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
        d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
        1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
        8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
        30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
        457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
        4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
        4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
        485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
        059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
        7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
        9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
        be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
        68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
        c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
        f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
        291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
        25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
        14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
        ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
        e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
        c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
        203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
        cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
        fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
        a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
        90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
        162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
        40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
        6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
        8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
        be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
        54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
        760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
        f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
        056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
        7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
        e221af44860018ab0856972e194cd934
        """
        |> String.replace([" ", "\n"], "")
        |> Base.decode16!(case: :lower)

      {:ok, protected_packet: protected_packet}
    end

    test "can be properly decrypted generically", %{protected_packet: protected_packet} do
      {:ok, %Quic.VersionIndependent.LongHeaderPacket{} = packet} =
        Quic.VersionIndependent.LongHeaderPacket.parse(protected_packet)

      assert packet.destination_connection_id == Base.decode16!("8394c8f03e515708", case: :lower)
      assert packet.source_connection_id == <<>>
      assert packet.version == 1

      assert <<64::size(7)>> =
               packet.version_specific_bits

      assert <<0, 68, 158, 123, 154, 236, 52, 209, 177, 201, 141, _::binary>> =
               packet.version_specific_data
    end

    test "can be properly decrypted", %{protected_packet: protected_packet} do
      {:ok, %Quic.VersionIndependent.LongHeaderPacket{} = packet} =
        Quic.VersionIndependent.LongHeaderPacket.parse(protected_packet)

      assert {:ok, 0x00} = Quic.Version1.validate_v1_packet(packet)

      assert {:ok, %Quic.Version1.InitialPacket{} = packet, <<>>} =
               Quic.Version1.InitialPacket.from_version_independent(packet)

      assert "c300000001088394c8f03e5157080000449e00000002" <> _ =
               Quic.Version1.InitialPacket.to_binary(packet)
               |> Base.encode16(case: :lower)

      assert packet.destination_connection_id == Base.decode16!("8394c8f03e515708", case: :lower)

      assert packet.length == 1182
      assert packet.packet_number_length == 3
      assert packet.packet_number == 2
      assert packet.reserved == 0

      unpadded_payload =
        """
        060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
        04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
        616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
        04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
        baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
        0d0010000e0403050306030203080408 050806002d00020101001c0002400100
        3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
        75300901100f088394c8f03e51570806 048000ffff
        """
        |> String.replace([" ", "\n"], "")
        |> Base.decode16!(case: :lower)

      assert unpadded_payload == packet.payload |> :binary.part(0, byte_size(unpadded_payload))

      [[<<0x06>>, client_hello] | _] = packet.frames

      Quic.Version1.TLS.parse_client_hello(binary_slice(client_hello, 4..-1//1))
      |> IO.inspect()
    end
  end

  describe "browser samples" do
    test "1" do
      packet =
        "c70000000108d110e201901bdab3030d121100428138d53cad813fafd9adee475f3ef4c75719042d7c0647e58a7bd568b2855ac1d94cb7e44d53c1abea5ecae6b7c79c8ce57ddb54dbaa3d78f1b7a371ce2465b5ca94ebb455694160e025449e8eef7e72a4e0c577ff12a2e570803bc33bb38101d6c83c97cdd8a523b024ad80d2c8428ba05314287033d4bd3acfca44ca9b984f242be0cb07b141c30ff5313c2d88a6ac06d2cc22d74d30aa3f50e6ff0147cde9ce6ed25688b8a7eb4e80b9734640428ca89102f4a22269ed691330c8fe885ce154170e64e0967c31336bdc8a7968af75d7453f4dceb6423c0635ac103b971788f71e3f493a7ca9aeb66776e75dcbb602be2fcaf626c169f64559bb98aba2ce39cea59b464de9eb57ba23b0df5d8a169d3c5aefbcf9fd7ecb38dcfd9a7529452f3262e92d0053ec89ca6ed1d5de316458aedc6a85307bb4b5578785547af8d896f2fa05e03ba2c95599db64a8a9fb3142cacfee32af405fbac638200b3b8790f468e0662ae17bf69a75b4d0ed27e28b75b25081fb49b3cda7a9b800ee8b33ada8279aa5e30c6e2844ef489220eff365625dbc847135271b4ca471187a44f72ef87223a83ab8d7cea5dabcdc0aa8c932fd05cd73030a8cdd4fc11dae9fdc4b3b86b8571bc78612c00124b41ddd1cb32ff9ddce9c9bf13c7ae4edef2f066cd7130c4c9aec097960f4646602e67412be21e8bf14289a9e2098210b08e47b386d9e59540bd42759629722e40c63f6e3bf530cc81169e6eb1634293e7446f3699cf8f56e397482d2f61b5cec4f5133a244e984fd4468bea1b733dec900ab3feb42b8e278a45d6d9f72fcf58f996b47151e01ee103e4f3bf9c147f4ba38c7f4c8c56e8945d340e09f5f5d608bb845af371ac73d951520e27e201111794f449478a1de4831b10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        |> Base.decode16!(case: :lower)

      {:ok, %Quic.VersionIndependent.LongHeaderPacket{} = packet} =
        Quic.VersionIndependent.LongHeaderPacket.parse(packet)

      assert {:ok, 0x00} = Quic.Version1.validate_v1_packet(packet)

      assert {:ok, %Quic.Version1.InitialPacket{} = packet, _} =
               Quic.Version1.InitialPacket.from_version_independent(packet)

      assert "c00000000108d110e201901bdab3030d121100428100" <> _ =
               Quic.Version1.InitialPacket.to_binary(packet)
               |> Base.encode16(case: :lower)

      assert packet.destination_connection_id == Base.decode16!("d110e201901bdab3", case: :lower)

      assert packet.length == 641
      assert packet.packet_number_length == 0
      assert packet.packet_number == 0
      assert packet.reserved == 0

      [[<<0x06>>, client_hello]] = packet.frames

      Quic.Version1.TLS.parse_client_hello(binary_slice(client_hello, 4..-1//1))
      |> IO.inspect()
    end
  end
end
