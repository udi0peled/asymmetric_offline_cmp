App_C_Flags := -O2 -Wall -Wextra -Wvla -Wno-unknown-pragmas -Wno-deprecated-declarations -I. 
App_Link_Flags := $(App_C_Flags) -lssl -lcrypto -pthread -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib

all: benchmark

primitives := algebraic_elements.o paillier_cryptosystem.o ring_pedersen_parameters.o  zkp_common.o zkp_paillier_blum_modulus.o zkp_ring_pedersen_param.o zkp_schnorr.o zkp_no_small_factors.o zkp_tight_range.o zkp_range_el_gamal_commitment.o zkp_el_gamal_dlog.o zkp_double_el_gamal.o zkp_operation_group_commitment_range.o zkp_well_formed_signature.o

protocol_phases := asymoff_key_generation.o asymoff_presigning.o asymoff_signing_cmp.o asymoff_signing_aggregate.o

benchmark.o: benchmark.c common.o tests.o primitives 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

cmp_protocol.o: cmp_protocol.c cmp_protocol.h common.o primitives 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

common.o: common.c common.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

algebraic_elements.o: algebraic_elements.c algebraic_elements.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

paillier_cryptosystem.o: paillier_cryptosystem.c paillier_cryptosystem.h algebraic_elements.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

ring_pedersen_parameters.o: ring_pedersen_parameters.c ring_pedersen_parameters.h paillier_cryptosystem.o algebraic_elements.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_common.o: zkp_common.c zkp_common.h algebraic_elements.o paillier_cryptosystem.o ring_pedersen_parameters.o 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_paillier_blum_modulus.o: zkp_paillier_blum_modulus.c zkp_paillier_blum_modulus.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_ring_pedersen_param.o: zkp_ring_pedersen_param.c zkp_ring_pedersen_param.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_schnorr.o: zkp_schnorr.c zkp_schnorr.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_encryption_in_range.o: zkp_encryption_in_range.c zkp_encryption_in_range.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_no_small_factors.o: zkp_no_small_factors.c zkp_no_small_factors.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_tight_range.o: zkp_tight_range.c zkp_tight_range.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_group_vs_paillier_range.o: zkp_group_vs_paillier_range.c zkp_group_vs_paillier_range.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_operation_group_commitment_range.o: zkp_operation_group_commitment_range.c zkp_operation_group_commitment_range.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_range_el_gamal_commitment.o: zkp_range_el_gamal_commitment.c zkp_range_el_gamal_commitment.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_el_gamal_dlog.o: zkp_el_gamal_dlog.c zkp_el_gamal_dlog.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_double_el_gamal.o: zkp_double_el_gamal.c zkp_double_el_gamal.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_well_formed_signature.o: zkp_well_formed_signature.c zkp_well_formed_signature.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


asymoff_protocol.o: asymoff_protocol.c asymoff_protocol.h $(primitives)
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

asymoff_key_generation.o: asymoff_key_generation.c asymoff_key_generation.h asymoff_protocol.o $(primitives)
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

asymoff_presigning.o: asymoff_presigning.c asymoff_presigning.h asymoff_protocol.o $(primitives)
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


asymoff_signing_cmp.o: asymoff_signing_cmp.c asymoff_signing_cmp.h asymoff_protocol.o $(primitives)
	@$(CC) $(App_C_Flags) -c $< -o $@ -Wno-unused-parameter
	@echo "CC   <=  $<"
	
asymoff_signing_aggregate.o: asymoff_signing_aggregate.c asymoff_signing_aggregate.h asymoff_protocol.o $(primitives)
	@$(CC) $(App_C_Flags) -c $< -o $@ -Wno-unused-parameter
	@echo "CC   <=  $<"
	

benchmark: benchmark.c common.o asymoff_protocol.o $(protocol_phases) $(primitives) 
	@${CC} $^ -o $@ $(App_Link_Flags)
	@echo "${CC} =>  $@"


clean:
	@rm -rf $(Bench_Name) *.o tests
