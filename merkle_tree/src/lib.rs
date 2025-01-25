use bincode::{Decode, Encode};
use solana_sdk::keccak::{self, HASH_BYTES};

/// A node of the Merkle tree
#[derive(Decode, Encode, Clone, PartialEq, Debug)]
pub enum TreeNode {
    Leaf(Vec<u8>),            // Leaves contain the actual account data
    Branch(Vec<TreeNode>),    // Branches contain the hash of the node
    Digest([u8; HASH_BYTES]), // Simple representation of subtrees
}

impl TreeNode {
    /// Creates a Merkle tree from the list of key account pairs.
    /// It assumes the list is sorted by keys and the account are wrapped in TreeNode
    pub fn new_from_entries(entries: Vec<([u8; 32], TreeNode)>) -> Self {
        // Split nodes in half recursively to create tree levels
        if entries.len() == 1 {
            return entries[0].1.clone();
        }

        let mid = entries.len() / 2;
        let left_entries = entries[..mid].to_vec();
        let right_entries = entries[mid..].to_vec();

        let left_node = TreeNode::new_from_entries(left_entries);
        let right_node = TreeNode::new_from_entries(right_entries);

        let mut branch = TreeNode::Branch(vec![]);
        branch.insert(vec![left_node, right_node]);

        branch
    }

    /// Inserts a set of children and turns this node into a branch.
    /// Ensuring fan-out is left to the user.
    pub fn insert(&mut self, children: Vec<TreeNode>) {
        if let TreeNode::Branch(branch) = self {
            branch.extend(children);
        } else {
            *self = TreeNode::Branch(children);
        }
    }

    pub fn hash(&self) -> [u8; HASH_BYTES] {
        match self {
            TreeNode::Branch(branch) => keccak::hash(
                &branch
                    .iter()
                    .map(|child| child.hash())
                    .collect::<Vec<[u8; HASH_BYTES]>>()
                    .concat(),
            )
            .to_bytes(),
            TreeNode::Digest(bytes) => *bytes,
            TreeNode::Leaf(data) => keccak::hash(data).to_bytes(),
        }
    }

    pub fn depth(&self) -> u8 {
        // Right-most branch should be the longest
        let mut i = 0;
        let mut node = Some(self);
        while let Some(TreeNode::Branch(branch)) = node {
            node = branch.last();
            i += 1;
        }

        i
    }
}

#[cfg(test)]
mod tests {
    use solana_sdk::pubkey::Pubkey;

    use super::*;

    #[test]
    fn test_create_whole_tree_manually() {
        // Create leaf nodes
        let leaf1 = TreeNode::Leaf(vec![1, 2, 3]);
        let leaf2 = TreeNode::Leaf(vec![4, 5, 6]);
        let leaf3 = TreeNode::Leaf(vec![7, 8, 9]);
        let leaf4 = TreeNode::Digest(TreeNode::Leaf(vec![10, 11, 12]).hash());

        // Create branch nodes
        let mut branch1 = TreeNode::Branch(vec![]);
        branch1.insert(vec![leaf1.clone(), leaf2.clone()]);

        let mut branch2 = TreeNode::Branch(vec![]);
        branch2.insert(vec![leaf3.clone(), leaf4.clone()]);

        // Create root node
        let mut root = TreeNode::Branch(vec![]);
        root.insert(vec![branch1.clone(), branch2.clone()]);

        // Check the structure of the tree
        if let TreeNode::Branch(children) = &root {
            assert_eq!(children.len(), 2);
            if let TreeNode::Branch(branch1_children) = &children[0] {
                assert_eq!(branch1_children.len(), 2);
                assert_eq!(branch1_children[0], leaf1);
                assert_eq!(branch1_children[1], leaf2);
            } else {
                panic!("Expected branch node");
            }
            if let TreeNode::Branch(branch2_children) = &children[1] {
                assert_eq!(branch2_children.len(), 2);
                assert_eq!(branch2_children[0], leaf3);
                assert_eq!(branch2_children[1], leaf4);
            } else {
                panic!("Expected branch node");
            }
        } else {
            panic!("Expected branch node");
        }

        // Check the hash of the root node
        let root_hash = root.hash();
        assert_eq!(root_hash.len(), HASH_BYTES);
        assert_eq!(root.depth(), 2);
    }

    #[test]
    fn test_create_whole_tree_automatically() {
        // Create leaf nodes
        let leaves = vec![
            (
                Pubkey::new_unique().to_bytes(),
                TreeNode::Leaf(vec![1, 2, 3]),
            ),
            (
                Pubkey::new_unique().to_bytes(),
                TreeNode::Leaf(vec![4, 5, 6]),
            ),
            (
                Pubkey::new_unique().to_bytes(),
                TreeNode::Leaf(vec![7, 8, 9]),
            ),
            (
                Pubkey::new_unique().to_bytes(),
                TreeNode::Digest(TreeNode::Leaf(vec![10, 11, 12]).hash()),
            ),
        ];

        let root = TreeNode::new_from_entries(leaves);

        // Check the hash of the root node
        let root_hash = root.hash();
        assert_eq!(root_hash.len(), HASH_BYTES);
    }
}
