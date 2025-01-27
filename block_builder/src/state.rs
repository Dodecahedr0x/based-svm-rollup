use std::collections::HashMap;

use bincode::{Decode, Encode};
use merkle_tree::TreeNode;
use solana_account::{Account, AccountSharedData, ReadableAccount, WritableAccount};
use solana_sdk::pubkey::Pubkey;

/// The state of the rollup used to execute a rollup block
/// It uses a sparse Merkle tree to store the state.
#[derive(Decode, Encode)]
pub struct RollupState {
    pub root: TreeNode,
    // Map pubkeys to account data
    pub accounts: HashMap<[u8; 32], TreeNode>,
}

impl RollupState {
    pub fn update_account(&mut self, pk: [u8; 32], account: RollupAccount) {
        if self.accounts.contains_key(&pk) {
            // The account already exists, just update it
            self.accounts.insert(pk, TreeNode::Leaf(account.into()));
        } else {
            // The account is new, recreate the tree with ordered keys to ensure reproducibility
            let mut new_keys: Vec<[u8; 32]> = self.accounts.keys().cloned().collect();
            new_keys.push(pk);
            new_keys.sort();

            let entries = new_keys
                .iter()
                .map(|k| {
                    (
                        *k,
                        self.accounts
                            .get(k)
                            .map_or(TreeNode::Leaf(RollupAccount::default().into()), |acc| {
                                acc.clone()
                            }),
                    )
                })
                .collect();

            // Recreate the root using the new set of accounts
            self.root = TreeNode::new_from_entries(entries);

            // Update the new empty account
            self.accounts.insert(pk, TreeNode::Leaf(account.into()));
        }
    }
}

#[derive(Decode, Encode)]
pub struct RollupAccount {
    /// lamports in the account
    pub lamports: u64,
    /// data held in this account
    pub data: Vec<u8>,
    /// the program that owns this account. If executable, the program that loads this account.
    pub owner: [u8; 32],
    /// this account's data contains a loaded program (and is now read-only)
    pub executable: bool,
    /// the epoch at which this account will next owe rent
    pub rent_epoch: u64,
}

impl RollupAccount {
    pub fn default() -> Self {
        RollupAccount {
            lamports: 0,
            data: vec![],
            owner: [0; 32],
            executable: false,
            rent_epoch: 0,
        }
    }
}

impl From<Vec<u8>> for RollupAccount {
    fn from(value: Vec<u8>) -> Self {
        bincode::decode_from_slice(&value, bincode::config::standard())
            .unwrap()
            .0
    }
}

impl From<Account> for RollupAccount {
    fn from(value: Account) -> Self {
        RollupAccount {
            lamports: value.lamports,
            data: value.data,
            owner: value.owner.to_bytes(),
            executable: value.executable,
            rent_epoch: value.rent_epoch,
        }
    }
}

impl From<AccountSharedData> for RollupAccount {
    fn from(value: AccountSharedData) -> Self {
        RollupAccount {
            lamports: value.lamports(),
            data: value.data().to_vec(),
            owner: value.owner().to_bytes(),
            executable: value.executable(),
            rent_epoch: value.rent_epoch(),
        }
    }
}

impl Into<Vec<u8>> for RollupAccount {
    fn into(self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}

impl Into<Account> for RollupAccount {
    fn into(self) -> Account {
        Account {
            lamports: self.lamports,
            data: self.data.clone(),
            owner: Pubkey::new_from_array(self.owner),
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        }
    }
}

impl Into<AccountSharedData> for RollupAccount {
    fn into(self) -> AccountSharedData {
        let mut account = AccountSharedData::new(
            self.lamports,
            self.data.len(),
            &Pubkey::new_from_array(self.owner),
        );
        account.set_executable(self.executable);
        account.set_rent_epoch(self.rent_epoch);
        account.set_data_from_slice(&self.data);

        account
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::pubkey::Pubkey;

    fn create_mock_account() -> RollupAccount {
        RollupAccount {
            lamports: 100,
            data: vec![1, 2, 3, 4, 5],
            owner: Pubkey::new_unique().to_bytes(),
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn test_update_state_with_new_account() {
        // Create a dummy account
        let pubkey = Pubkey::new_unique();
        let account = create_mock_account();

        // Serialize the account
        let serialized_account = account.into();
        let account_node = TreeNode::Leaf(serialized_account);

        // Create an initial RollupState
        let mut rollup_state = RollupState {
            root: TreeNode::Branch(vec![]),
            accounts: HashMap::new(),
        };

        // Insert the new account into the state
        rollup_state
            .accounts
            .insert(pubkey.to_bytes(), account_node.clone());

        // Update the root of the Merkle tree
        rollup_state.root.insert(vec![account_node.clone()]);

        // Check if the account was inserted correctly
        assert!(rollup_state.accounts.contains_key(&pubkey.to_bytes()));
        assert_eq!(
            rollup_state.accounts.get(&pubkey.to_bytes()).unwrap(),
            &account_node
        );
    }

    #[test]
    fn test_update_state_changes_root_hash() {
        // Create leaf nodes
        let leaves = vec![
            (
                Pubkey::new_unique().to_bytes(),
                TreeNode::Leaf(create_mock_account().into()),
            ),
            (
                Pubkey::new_unique().to_bytes(),
                TreeNode::Leaf(create_mock_account().into()),
            ),
            (
                Pubkey::new_unique().to_bytes(),
                TreeNode::Leaf(create_mock_account().into()),
            ),
            (
                Pubkey::new_unique().to_bytes(),
                TreeNode::Leaf(create_mock_account().into()),
            ),
        ];
        let root = TreeNode::new_from_entries(leaves.clone());

        // Create an initial RollupState
        let mut rollup_state = RollupState {
            root,
            accounts: HashMap::from_iter(leaves.iter().map(|(pk, node)| (*pk, node.clone()))),
        };

        let old_root = rollup_state.root.hash();

        // Update an account
        rollup_state
            .accounts
            .insert(leaves[0].0, TreeNode::Leaf(create_mock_account().into()));

        // Root must be different
        assert_ne!(rollup_state.root.hash(), old_root);
    }
}
