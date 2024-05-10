use super::*;
use zk_evm_abstractions::auxiliary::*;
use zk_evm_abstractions::queries::*;
use zk_evm_abstractions::vm::*;
use zkevm_opcode_defs::system_params::*;
use zkevm_opcode_defs::PrecompileCallABI;

fn fill_memory<M: Memory>(
    tuples: Vec<[[u8; 32]; 6]>,
    page: u32,
    memory: &mut M,
) -> u16 {
    let mut location = MemoryLocation {
        page: MemoryPage(page),
        index: MemoryIndex(0),
        memory_type: MemoryType::Heap,
    };

    for i in 0..tuples.len() {
        for j in 0..6 {
            let query = MemoryQuery {
                timestamp: Timestamp(0u32),
                location,
                value: U256::from_big_endian(&tuples[i][j]),
                rw_flag: true,
                value_is_pointer: false,
            };
            let _ = memory.execute_partial_query((6*i+j) as u32, query);
            location.index.0 += 1;
        }
    }

    6 * tuples.len() as u16
}

fn ecpairing_test_inner(
    tuples: Vec<[[u8; 32]; 6]>,
    expect_ok: bool,
    expected_result: [u8; 32],
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<false>;
    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    // fill the memory
    let num_words_used = fill_memory(tuples, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 1,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(ECPAIRING_INNER_FUNCTION_PRECOMPILE_ADDRESS as u64);

    let precompile_query = LogQuery {
        timestamp: Timestamp(1u32),
        tx_number_in_block: 0,
        shard_id: 0,
        aux_byte: PRECOMPILE_AUX_BYTE,
        address,
        key: precompile_call_params_encoded,
        read_value: U256::zero(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    };

    let _ = precompiles_processor.execute_precompile(4, precompile_query, &mut memory);

    let range = 0u32..(num_words_used as u32 + 2);
    let content = memory.dump_page_content(page_number, range.clone());
    let content_len = content.len();
    let ok_or_error_marker = content[content_len - 2];
    let output = content[content_len - 1];

    if expect_ok {
        let mut buffer = [0u8; 32];
        U256::one().to_big_endian(&mut buffer);
        assert_eq!(ok_or_error_marker, buffer);
        assert_eq!(&output, &expected_result);
    } else {
        let mut buffer = [0u8; 32];
        U256::zero().to_big_endian(&mut buffer);
        assert_eq!(ok_or_error_marker, buffer);
        assert_eq!(&expected_result[..], &[0u8; 32]);
    }

    (content, range)
}

fn ecpairing_test_inner_from_raw(
    raw_input: &str,
    raw_output: &str,
    expect_ok: bool,
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let input_bytes = hex::decode(raw_input).unwrap();

    assert!(input_bytes.len() % 192 == 0, "number of input bytes must be divisible by 192");
    
    let tuples_number = input_bytes.len() / 192;
    let mut tuples = vec![[[0u8; 32]; 6]; tuples_number];

    for i in 0..tuples_number {
        let x1: [u8; 32] = input_bytes[192*i..192*i+32].try_into().unwrap();
        let y1: [u8; 32] = input_bytes[192*i+32..192*i+64].try_into().unwrap();
        let x2: [u8; 32] = input_bytes[192*i+64..192*i+96].try_into().unwrap();
        let y2: [u8; 32] = input_bytes[192*i+96..192*i+128].try_into().unwrap();
        let x3: [u8; 32] = input_bytes[192*i+128..192*i+160].try_into().unwrap();
        let y3: [u8; 32] = input_bytes[192*i+160..192*i+192].try_into().unwrap();

        tuples[i] = [x1, y1, x2, y2, x3, y3];
    }

    let expected_result: [u8; 32] = hex::decode(raw_output).unwrap().try_into().unwrap();

    ecpairing_test_inner(tuples, expect_ok, expected_result)
}

#[test]
fn test_valid() {
    let raw_input = "2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f61fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d92bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f902fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e000000000000000000000000000000000000000000000000000000000000000130644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd451971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc72a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea223a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc";
    let raw_output = "0000000000000000000000000000000000000000000000000000000000000001";
    let (content, range) = ecpairing_test_inner_from_raw(raw_input, &raw_output, true);
    pretty_print_memory_dump(&content, range);
}
