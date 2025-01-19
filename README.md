# Based SVM Rollup

This project started in the context of the [Turbin3 Advanced SVM cohort](https://www.turbin3.com/) of Q1 2025. The original idea is to create a **based SVM rollup with ZK validation on Solana**.

## Introduction

The term _rollup_ is generally used to mean a blockchain where the canonical state is decided by a [validating bridge](https://stonecoldpat.github.io/images/validatingbridges.pdf) on a base layer (often an L1 blockchain). The most common verification mechanism for validating bridges are called fraud proofs and validity proofs. In fraud proof, some participant can submit evidence of invalid state transitions so that the validating bridge rejects the commited block. In validity proof, block proposer must also submit a cryptographic proof that the block they propose is valid. We focus on validity proofs because they are safer and now have a lot of great tools.

The most common design for submitting blocks to validating bridge is to have a single trusted operator called the _sequencer_ send a commitment of the block. However this design is centralized and partially defeats the purpose of blockchains. For this reason, researchers came up with a design called [_based rollups_](https://ethresear.ch/t/based-rollups-superpowers-from-l1-sequencing/15016) where new blocks are proposed directly on the base layer. Single sequencers can commit to transactions faster than based rollups because they are not limited by the L1, but since we're building on Solana this is less of a concern so we choose the most decentralized option.

Finally, as this work is done in the context of the Turbin3 Advanced SVM cohort, we choose to use the SVM for the rollup, as it will allow use to dive deeper into the inner mechanics of the VM.

## High level design

The structure of the project looks like this:

- A Solana program will enable participants to submit rollup blocks and will implement a heuristic to select the block that will be commited.
- Participants will use [Aerius zkSVM](https://github.com/aerius-labs/zkSVM) to execute the transactions of the commited block and generate the proof.
- The proof can then be verified using [Succint SP1](https://blog.succinct.xyz/solana-sp1/) verifier to ensure that the block is valid and update the validating bridge.
- Off chain databases can then be updated using the commited transactions.
