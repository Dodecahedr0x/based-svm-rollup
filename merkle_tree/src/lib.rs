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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_whole_tree() {
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
    }
}
