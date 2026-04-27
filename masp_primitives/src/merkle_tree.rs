//! Implementation of a Merkle tree of commitments used to prove the existence of notes.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use borsh::BorshSchema;
use borsh::schema::Declaration;
use borsh::schema::Definition;
use borsh::schema::Fields;
use borsh::schema::add_definition;
use borsh::{BorshDeserialize, BorshSerialize};
use core::convert::TryFrom;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::iter::repeat;
use zcash_encoding::{Optional, Vector};

use crate::sapling::SAPLING_COMMITMENT_TREE_DEPTH;

/// A hashable node within a Merkle tree.
pub trait Hashable: Clone + Copy {
    /// Parses a node from the given byte source.
    fn read<R: Read>(reader: R) -> io::Result<Self>;

    /// Serializes this node.
    fn write<W: Write>(&self, writer: W) -> io::Result<()>;

    /// Returns the parent node within the tree of the two given nodes.
    fn combine(_: usize, _: &Self, _: &Self) -> Self;

    /// Returns a blank leaf node.
    fn blank() -> Self;

    /// Returns the empty root for the given depth.
    fn empty_root(_: usize) -> Self;
}

/// A hashable node within a Merkle tree.
pub trait HashSer {
    /// Parses a node from the given byte source.
    fn read<R: Read>(reader: R) -> io::Result<Self>
    where
        Self: Sized;

    /// Serializes this node.
    fn write<W: Write>(&self, writer: W) -> io::Result<()>;
}

impl<T> Hashable for T
where
    T: incrementalmerkletree::Hashable + HashSer + Copy,
{
    /// Parses a node from the given byte source.
    fn read<R: Read>(reader: R) -> io::Result<Self> {
        <Self as HashSer>::read(reader)
    }

    /// Serializes this node.
    fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        <Self as HashSer>::write(self, writer)
    }

    /// Returns the parent node within the tree of the two given nodes.
    fn combine(alt: usize, lhs: &Self, rhs: &Self) -> Self {
        <Self as incrementalmerkletree::Hashable>::combine(
            incrementalmerkletree::Level::from(
                u8::try_from(alt).expect("Tree heights greater than 255 are unsupported."),
            ),
            lhs,
            rhs,
        )
    }

    /// Returns a blank leaf node.
    fn blank() -> Self {
        <Self as incrementalmerkletree::Hashable>::empty_leaf()
    }

    /// Returns the empty root for the given depth.
    fn empty_root(alt: usize) -> Self {
        <Self as incrementalmerkletree::Hashable>::empty_root(incrementalmerkletree::Level::from(
            u8::try_from(alt).expect("Tree heights greater than 255 are unsupported."),
        ))
    }
}

struct PathFiller<Node: Hashable> {
    queue: VecDeque<Node>,
}

impl<Node: Hashable> PathFiller<Node> {
    fn empty() -> Self {
        PathFiller {
            queue: VecDeque::new(),
        }
    }

    fn next(&mut self, depth: usize) -> Node {
        self.queue
            .pop_front()
            .unwrap_or_else(|| Node::empty_root(depth))
    }
}

/// An immutable commitment tree
#[derive(Clone, Debug, Default)]
pub struct FrozenCommitmentTree<Node>(Vec<Node>, usize);

impl<Node: Hashable> FrozenCommitmentTree<Node> {
    /// Construct a commitment tree with the given leaf nodes
    pub fn new(leafs: &[Node]) -> Self {
        // This capacity is sufficient to hold a Merkle tree (where an empty node
        // is added onto some rows to ensure that they are of even size) with the
        // given number of leaves. This follows from the identity ceil(ceil(x/m)/n)=ceil(x/(mn))
        let mut tree = Vec::with_capacity(leafs.len() * 2 + SAPLING_COMMITMENT_TREE_DEPTH - 1);
        tree.extend_from_slice(leafs);
        // Infer the rest of the tree
        Self::complete(tree, 0, leafs.len(), 0, leafs.len())
    }
    /// Merge the n-1 full Merkle trees with the last possibly unfilled one. All
    /// full trees must have the same size which must be a power of 2 and the
    /// tree must be smaller than this size.
    pub fn merge(subtrees: &[FrozenCommitmentTree<Node>]) -> Self {
        if subtrees.is_empty() {
            return Self(Vec::new(), 0);
        } else if subtrees.len() == 1 {
            return subtrees[0].clone();
        }
        let size = subtrees[0].size();
        assert!(size.is_power_of_two());
        for subtree in subtrees.iter().rev().skip(1) {
            assert_eq!(subtree.size(), size);
        }
        // Combine the 1 or more supplied subtrees
        let mut height = 0;
        let mut prev_first_start = 0;
        let mut prev_first_width = subtrees[0].size();
        let mut prev_last_start = 0;
        let mut prev_last_width = subtrees.last().unwrap().size();
        let mut prev_start = 0;
        let mut prev_width = (subtrees.len() - 1) * prev_first_width + prev_last_width;
        let leafs = prev_width;
        let mut tree = Vec::with_capacity(leafs * 2 + SAPLING_COMMITMENT_TREE_DEPTH - 1);
        loop {
            // Need to make sure that right child is present for parent
            if prev_last_width % 2 == 1 && prev_first_width > 1 {
                prev_last_width += 1;
                prev_width += 1;
            }
            // Combine all the rows at the current level
            for subtree in &subtrees[0..(subtrees.len() - 1)] {
                tree.extend_from_slice(
                    &subtree.0[prev_first_start..(prev_first_start + prev_first_width)],
                );
            }
            tree.extend_from_slice(
                &subtrees.last().unwrap().0[prev_last_start..(prev_last_start + prev_last_width)],
            );
            // Quit when we are the top of the full trees
            if prev_first_width == 1 {
                break;
            }
            // Update our positions on the full and unfull trees
            prev_first_start += prev_first_width;
            prev_first_width /= 2;
            prev_last_start += prev_last_width;
            prev_last_width /= 2;
            prev_start += prev_width;
            prev_width /= 2;
            height += 1;
        }
        // Now that we have taken as many levels as possible from the
        // supplied subtrees, infer the rest
        Self::complete(tree, prev_start, prev_width, height, leafs)
    }
    /// Complete the construction of given Merkle tree given the highest row data
    fn complete(
        mut tree: Vec<Node>,
        mut prev_start: usize,
        mut prev_width: usize,
        heightp: usize,
        leafs: usize,
    ) -> Self {
        // Add higher and higher rows of the Merkle tree
        for height in heightp..SAPLING_COMMITMENT_TREE_DEPTH {
            if prev_width % 2 == 1 {
                // Add a dummy for the right-most parent's right child
                prev_width += 1;
                tree.push(Node::empty_root(height))
            }
            for j in 0..(prev_width / 2) {
                // Add the nodes of the next row dependent upon previous row
                let comb = Node::combine(
                    height,
                    &tree[prev_start + 2 * j],
                    &tree[prev_start + 2 * j + 1],
                );
                tree.push(comb);
            }
            // Next row will be adjacent to current row in vector
            prev_start += prev_width;
            prev_width /= 2;
        }
        Self(tree, leafs)
    }
    /// Get the root node of the commitment tree
    pub fn root(&self) -> Node {
        self.0
            .last()
            .cloned()
            .unwrap_or_else(|| Node::empty_root(SAPLING_COMMITMENT_TREE_DEPTH))
    }
    /// Construct a merkle path to the given position in commitment tree
    pub fn path(&self, mut pos: usize) -> MerklePath<Node> {
        let mut path = MerklePath {
            auth_path: vec![],
            position: pos as u64,
        };
        let mut start = 0;
        let mut width = self.1;

        for height in 0..SAPLING_COMMITMENT_TREE_DEPTH {
            if width % 2 == 1 {
                width += 1;
            }
            if pos % 2 == 0 {
                // The current node is a left child
                let node = if pos + 1 < width {
                    // Node is within current row
                    self.0[start + pos + 1]
                } else {
                    // Node is to the right of current row
                    Node::empty_root(height)
                };
                path.auth_path.push((node, false));
            } else {
                // The current node is a right child
                let node = if pos - 1 < width {
                    self.0[start + pos - 1]
                } else {
                    Node::empty_root(height)
                };
                path.auth_path.push((node, true));
            }
            // Move to the parent of the current node
            start += width;
            width /= 2;
            pos /= 2;
        }
        path
    }
    /// Returns the number of leaf nodes in the tree.
    pub fn size(&self) -> usize {
        self.1
    }
}

impl<Node: BorshSerialize> BorshSerialize for FrozenCommitmentTree<Node> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        (&self.0, self.1).serialize(writer)
    }
}

impl<Node: BorshDeserialize> BorshDeserialize for FrozenCommitmentTree<Node> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let tup: (Vec<Node>, usize) = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self(tup.0, tup.1))
    }
}

/// A Merkle tree of note commitments.
///
/// The depth of the Merkle tree is fixed at 32, equal to the depth of the Sapling
/// commitment tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentTree<Node> {
    pub(crate) left: Option<Node>,
    pub(crate) right: Option<Node>,
    pub(crate) parents: Vec<Option<Node>>,
}

impl<Node> CommitmentTree<Node> {
    /// Creates an empty tree.
    pub fn empty() -> Self {
        CommitmentTree {
            left: None,
            right: None,
            parents: vec![],
        }
    }

    /// Convert this tree into an [`incrementalmerkletree`] data structure.
    pub fn into_incrementalmerkletree(
        self,
    ) -> incrementalmerkletree::frontier::CommitmentTree<
        Node,
        { SAPLING_COMMITMENT_TREE_DEPTH as u8 },
    > {
        incrementalmerkletree::frontier::CommitmentTree::from_parts(
            self.left,
            self.right,
            self.parents,
        )
        // NB: this can only fail if the parents len is
        // greater than SAPLING_COMMITMENT_TREE_DEPTH,
        // which will never happen
        .unwrap()
    }

    /// Convert this tree from an [`incrementalmerkletree`] data structure.
    pub fn from_incrementalmerkletree(
        tree: &incrementalmerkletree::frontier::CommitmentTree<
            Node,
            { SAPLING_COMMITMENT_TREE_DEPTH as u8 },
        >,
    ) -> CommitmentTree<Node>
    where
        Node: Clone,
    {
        CommitmentTree {
            left: tree.left().as_ref().cloned(),
            right: tree.right().as_ref().cloned(),
            parents: tree.parents().clone(),
        }
    }

    /// Returns the number of leaf nodes in the tree.
    pub fn size(&self) -> usize {
        self.parents.iter().enumerate().fold(
            match (self.left.as_ref(), self.right.as_ref()) {
                (None, None) => 0,
                (Some(_), None) => 1,
                (Some(_), Some(_)) => 2,
                (None, Some(_)) => unreachable!(),
            },
            |acc, (i, p)| {
                // Treat occupation of parents array as a binary number
                // (right-shifted by 1)
                acc + if p.is_some() { 1 << (i + 1) } else { 0 }
            },
        )
    }

    fn is_complete(&self, depth: usize) -> bool {
        if depth == 0 {
            self.left.is_some() && self.right.is_none() && self.parents.is_empty()
        } else {
            self.left.is_some()
                && self.right.is_some()
                && self
                    .parents
                    .iter()
                    .chain(repeat(&None))
                    .take(depth - 1)
                    .all(|p| p.is_some())
        }
    }
}

impl<Node: Hashable> CommitmentTree<Node> {
    /// Reads a `CommitmentTree` from its serialized form.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let left = Optional::read(&mut reader, Node::read)?;
        let right = Optional::read(&mut reader, Node::read)?;
        let parents = Vector::read(&mut reader, |r| Optional::read(r, Node::read))?;

        Ok(CommitmentTree {
            left,
            right,
            parents,
        })
    }

    /// Serializes this tree as an array of bytes.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        Optional::write(&mut writer, self.left, |w, n| n.write(w))?;
        Optional::write(&mut writer, self.right, |w, n| n.write(w))?;
        Vector::write(&mut writer, &self.parents, |w, e| {
            Optional::write(w, *e, |w, n| n.write(w))
        })
    }

    /// Adds a leaf node to the tree.
    ///
    /// Returns an error if the tree is full.
    pub fn append(&mut self, node: Node) -> Result<(), ()> {
        self.append_inner(node, SAPLING_COMMITMENT_TREE_DEPTH)
    }

    fn append_inner(&mut self, node: Node, depth: usize) -> Result<(), ()> {
        if self.is_complete(depth) {
            // Tree is full
            return Err(());
        }

        match (self.left, self.right) {
            (None, _) => self.left = Some(node),
            (_, None) => self.right = Some(node),
            (Some(l), Some(r)) => {
                let mut combined = Node::combine(0, &l, &r);
                self.left = Some(node);
                self.right = None;

                for i in 0..depth {
                    if i < self.parents.len() {
                        if let Some(p) = self.parents[i] {
                            combined = Node::combine(i + 1, &p, &combined);
                            self.parents[i] = None;
                        } else {
                            self.parents[i] = Some(combined);
                            break;
                        }
                    } else {
                        self.parents.push(Some(combined));
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns the current root of the tree.
    pub fn root(&self) -> Node {
        self.root_inner(SAPLING_COMMITMENT_TREE_DEPTH, PathFiller::empty())
    }

    fn root_inner(&self, depth: usize, mut filler: PathFiller<Node>) -> Node {
        assert!(depth > 0);

        // 1) Hash left and right leaves together.
        //    - Empty leaves are used as needed.
        let leaf_root = Node::combine(
            0,
            &self.left.unwrap_or_else(|| filler.next(0)),
            &self.right.unwrap_or_else(|| filler.next(0)),
        );

        // 2) Extend the parents to the desired depth with None values, then hash from leaf to
        //    root. Roots of the empty subtrees are used as needed.
        self.parents
            .iter()
            .chain(repeat(&None))
            .take(depth - 1)
            .enumerate()
            .fold(leaf_root, |root, (i, p)| match p {
                Some(node) => Node::combine(i + 1, node, &root),
                None => Node::combine(i + 1, &root, &filler.next(i + 1)),
            })
    }
}

impl<Node: Hashable> BorshSerialize for CommitmentTree<Node> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write(writer)
    }
}

impl<Node: Hashable> BorshDeserialize for CommitmentTree<Node> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        Self::read(reader)
    }
}

/// An updatable witness to a path from a position in a particular [`CommitmentTree`].
///
/// Appending the same commitments in the same order to both the original
/// [`CommitmentTree`] and this `IncrementalWitness` will result in a witness to the path
/// from the target position to the root of the updated tree.
///
/// # Examples
///
/// ```
/// use ff::{Field, PrimeField};
/// use rand_core::OsRng;
/// use masp_primitives::{
///     merkle_tree::{CommitmentTree, IncrementalWitness},
///     sapling::Node,
/// };
///
/// let mut rng = OsRng;
///
/// let mut tree = CommitmentTree::<Node>::empty();
///
/// tree.append(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
/// tree.append(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
/// let mut witness = IncrementalWitness::from_tree(&tree);
/// assert_eq!(witness.position(), 1);
/// assert_eq!(tree.root(), witness.root());
///
/// let cmu = Node::from_scalar(bls12_381::Scalar::random(&mut rng));
/// tree.append(cmu);
/// witness.append(cmu);
/// assert_eq!(tree.root(), witness.root());
/// ```
#[derive(Clone, Debug)]
pub struct IncrementalWitness<Node: Hashable> {
    tree: CommitmentTree<Node>,
    filled: Vec<Node>,
    cursor_depth: usize,
    cursor: Option<CommitmentTree<Node>>,
}

impl<Node: Hashable> IncrementalWitness<Node> {
    /// Creates an `IncrementalWitness` for the most recent commitment added to the given
    /// [`CommitmentTree`].
    pub fn from_tree(tree: &CommitmentTree<Node>) -> IncrementalWitness<Node> {
        IncrementalWitness {
            tree: tree.clone(),
            filled: vec![],
            cursor_depth: 0,
            cursor: None,
        }
    }

    /// Convert this witness into an [`incrementalmerkletree`] data structure.
    pub fn into_incrementalmerkletree(
        self,
    ) -> incrementalmerkletree::witness::IncrementalWitness<
        Node,
        { SAPLING_COMMITMENT_TREE_DEPTH as u8 },
    > {
        incrementalmerkletree::witness::IncrementalWitness::from_parts(
            self.tree.into_incrementalmerkletree(),
            self.filled,
            self.cursor.map(CommitmentTree::into_incrementalmerkletree),
        )
        // NB: this can only fail if the parents len is
        // greater than SAPLING_COMMITMENT_TREE_DEPTH,
        // which will never happen
        .unwrap()
    }

    /// Convert this witness from an [`incrementalmerkletree`] data structure.
    pub fn from_incrementalmerkletree(
        witness: &incrementalmerkletree::witness::IncrementalWitness<
            Node,
            { SAPLING_COMMITMENT_TREE_DEPTH as u8 },
        >,
    ) -> IncrementalWitness<Node>
    where
        Node: Clone,
    {
        let mut witness = IncrementalWitness {
            tree: CommitmentTree::from_incrementalmerkletree(witness.tree()),
            filled: witness.filled().clone(),
            cursor: witness
                .cursor()
                .as_ref()
                .map(CommitmentTree::from_incrementalmerkletree),
            cursor_depth: 0,
        };

        witness.cursor_depth = witness.next_depth();

        witness
    }

    /// Reads an `IncrementalWitness` from its serialized form.
    #[allow(clippy::redundant_closure)]
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let tree = CommitmentTree::read(&mut reader)?;
        let filled = Vector::read(&mut reader, |r| Node::read(r))?;
        let cursor = Optional::read(&mut reader, CommitmentTree::read)?;

        let mut witness = IncrementalWitness {
            tree,
            filled,
            cursor_depth: 0,
            cursor,
        };

        witness.cursor_depth = witness.next_depth();

        Ok(witness)
    }

    /// Serializes this `IncrementalWitness` as an array of bytes.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.tree.write(&mut writer)?;
        Vector::write(&mut writer, &self.filled, |w, n| n.write(w))?;
        Optional::write(&mut writer, self.cursor.as_ref(), |w, t| t.write(w))
    }

    /// Returns the position of the witnessed leaf node in the commitment tree.
    pub fn position(&self) -> usize {
        self.tree.size() - 1
    }

    fn filler(&self) -> PathFiller<Node> {
        let cursor_root = self
            .cursor
            .as_ref()
            .map(|c| c.root_inner(self.cursor_depth, PathFiller::empty()));

        PathFiller {
            queue: self.filled.iter().cloned().chain(cursor_root).collect(),
        }
    }

    /// Finds the next "depth" of an unfilled subtree.
    fn next_depth(&self) -> usize {
        let mut skip = self.filled.len();

        if self.tree.left.is_none() {
            if skip > 0 {
                skip -= 1;
            } else {
                return 0;
            }
        }

        if self.tree.right.is_none() {
            if skip > 0 {
                skip -= 1;
            } else {
                return 0;
            }
        }

        let mut d = 1;
        for p in &self.tree.parents {
            if p.is_none() {
                if skip > 0 {
                    skip -= 1;
                } else {
                    return d;
                }
            }
            d += 1;
        }

        d + skip
    }

    /// Tracks a leaf node that has been added to the underlying tree.
    ///
    /// Returns an error if the tree is full.
    pub fn append(&mut self, node: Node) -> Result<(), ()> {
        self.append_inner(node, SAPLING_COMMITMENT_TREE_DEPTH)
    }

    fn append_inner(&mut self, node: Node, depth: usize) -> Result<(), ()> {
        if let Some(mut cursor) = self.cursor.take() {
            cursor
                .append_inner(node, depth)
                .expect("cursor should not be full");
            if cursor.is_complete(self.cursor_depth) {
                self.filled
                    .push(cursor.root_inner(self.cursor_depth, PathFiller::empty()));
            } else {
                self.cursor = Some(cursor);
            }
        } else {
            self.cursor_depth = self.next_depth();
            if self.cursor_depth >= depth {
                // Tree is full
                return Err(());
            }

            if self.cursor_depth == 0 {
                self.filled.push(node);
            } else {
                let mut cursor = CommitmentTree::empty();
                cursor
                    .append_inner(node, depth)
                    .expect("cursor should not be full");
                self.cursor = Some(cursor);
            }
        }

        Ok(())
    }

    /// Returns the current root of the tree corresponding to the witness.
    pub fn root(&self) -> Node {
        self.root_inner(SAPLING_COMMITMENT_TREE_DEPTH)
    }

    fn root_inner(&self, depth: usize) -> Node {
        self.tree.root_inner(depth, self.filler())
    }

    /// Returns the current witness, or None if the tree is empty.
    pub fn path(&self) -> Option<MerklePath<Node>> {
        self.path_inner(SAPLING_COMMITMENT_TREE_DEPTH)
    }

    fn path_inner(&self, depth: usize) -> Option<MerklePath<Node>> {
        let mut filler = self.filler();
        let mut auth_path = Vec::new();

        if let Some(node) = self.tree.left {
            if self.tree.right.is_some() {
                auth_path.push((node, true));
            } else {
                auth_path.push((filler.next(0), false));
            }
        } else {
            // Can't create an authentication path for the beginning of the tree
            return None;
        }

        for (i, p) in self
            .tree
            .parents
            .iter()
            .chain(repeat(&None))
            .take(depth - 1)
            .enumerate()
        {
            auth_path.push(match p {
                Some(node) => (*node, true),
                None => (filler.next(i + 1), false),
            });
        }

        assert_eq!(auth_path.len(), depth);

        Some(MerklePath::from_path(auth_path, self.position() as u64))
    }
}

impl<Node: Hashable> BorshSerialize for IncrementalWitness<Node> {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.write(writer)
    }
}

impl<Node: Hashable> BorshDeserialize for IncrementalWitness<Node> {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        Self::read(reader)
    }
}

/// A path from a position in a particular commitment tree to the root of that tree.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath<Node> {
    pub auth_path: Vec<(Node, bool)>,
    pub position: u64,
}

impl<Node: Hashable> MerklePath<Node> {
    /// Constructs a Merkle path directly from a path and position.
    pub fn from_path(auth_path: Vec<(Node, bool)>, position: u64) -> Self {
        MerklePath {
            auth_path,
            position,
        }
    }

    /// Reads a Merkle path from its serialized form.
    pub fn from_slice(witness: &[u8]) -> Result<Self, ()> {
        Self::from_slice_with_depth(witness, SAPLING_COMMITMENT_TREE_DEPTH)
    }

    fn from_slice_with_depth(mut witness: &[u8], depth: usize) -> Result<Self, ()> {
        let path = Self::deserialize(&mut witness).map_err(|_| ())?;
        if path.auth_path.len() != depth {
            return Err(());
        }
        // The witness should be empty now; if it wasn't, the caller would
        // have provided more information than they should have, indicating
        // a bug downstream
        if witness.is_empty() {
            Ok(path)
        } else {
            Err(())
        }
    }

    /// Returns the root of the tree corresponding to this path applied to `leaf`.
    pub fn root(&self, leaf: Node) -> Node {
        self.auth_path
            .iter()
            .enumerate()
            .fold(
                leaf,
                |root, (i, (p, leaf_is_on_right))| match leaf_is_on_right {
                    false => Node::combine(i, &root, p),
                    true => Node::combine(i, p, &root),
                },
            )
    }
}

impl<Node: Hashable> BorshDeserialize for MerklePath<Node> {
    fn deserialize_reader<R: Read>(witness: &mut R) -> Result<Self, std::io::Error> {
        // Skip the first byte, which should be "depth" to signify the length of
        // the following vector of sibling hashes.
        let depth = witness.read_u8()? as usize;

        // Begin to construct the authentication path
        // Do not use any data in the witness after the expected depth
        let mut iter = vec![];
        let _ = witness
            .take((33 * depth + 8usize) as u64)
            .read_to_end(&mut iter)?;
        let iter = iter.chunks_exact(33);
        // Read the position from the witness
        let position = iter.remainder().read_u64::<LittleEndian>()?;

        // The vector works in reverse
        let mut auth_path = iter
            .rev()
            .map(|bytes| {
                // Length of inner vector should be a scalar field element.
                if bytes[0] == 32 {
                    // Sibling node should be an element of Fr
                    Node::read(&bytes[1..])
                        .map(|sibling| {
                            // Set the value in the auth path; we put false here
                            // for now (signifying the position bit) which we'll
                            // fill in later.
                            (sibling, false)
                        })
                        .map_err(|_| ())
                } else {
                    Err(())
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        if auth_path.len() != depth {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }

        // Given the position, let's finish constructing the authentication
        // path
        let mut tmp = position;
        for entry in auth_path.iter_mut() {
            entry.1 = (tmp & 1) == 1;
            tmp >>= 1;
        }

        Ok(MerklePath {
            auth_path,
            position,
        })
    }
}

impl<Node: Hashable> BorshSerialize for MerklePath<Node> {
    fn serialize<W: Write>(&self, witness: &mut W) -> Result<(), std::io::Error> {
        let mut position = 0u64;
        // Write path length
        witness.write_u8(self.auth_path.len() as u8)?;
        for (i, (node, b)) in self.auth_path.iter().enumerate().rev() {
            // Write node into temporary object to measure data length
            let mut node_bytes = Vec::new();
            node.write(&mut node_bytes)?;
            // Write node length
            witness.write_u8(node_bytes.len() as u8)?;
            // Write node data
            witness.write_all(&node_bytes)?;
            position |= (*b as u64) << i;
        }
        // Write bit vector indicating positions
        witness.write_u64::<LittleEndian>(position)?;
        Ok(())
    }
}

impl<Node: BorshSchema> BorshSchema for MerklePath<Node> {
    fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
        let definition = Definition::Sequence {
            length_width: 1,
            length_range: ((u8::MIN as u64)..=(u8::MAX as u64)),
            elements: <(u8, Node)>::declaration(),
        };
        add_definition(
            format!(r#"{}::auth_path"#, Self::declaration()),
            definition,
            definitions,
        );
        let definition = Definition::Struct {
            fields: Fields::NamedFields(vec![
                (
                    "auth_path".into(),
                    format!(r#"{}::auth_path"#, Self::declaration()),
                ),
                ("position".into(), u64::declaration()),
            ]),
        };
        add_definition(Self::declaration(), definition, definitions);
        <(u8, Node)>::add_definitions_recursively(definitions);
        u64::add_definitions_recursively(definitions);
    }

    fn declaration() -> Declaration {
        format!(r#"MerklePath<{}>"#, Node::declaration())
    }
}

#[cfg(test)]
mod tests {

    use ff::PrimeField;
    use proptest::prelude::*;
    use serde_json::Value;
    use std::convert::TryInto;

    use crate::sapling::{Node, SAPLING_COMMITMENT_TREE_DEPTH, testing::arb_node};

    use super::{
        CommitmentTree, FrozenCommitmentTree, Hashable, IncrementalWitness, PathFiller,
        testing::{TestNode, arb_commitment_tree},
    };

    #[test]
    fn test_frozen_tree() {
        let commitments = [
            "b02310f2e087e55bfd07ef5e242e3b87ee5d00c9ab52f61e6bd42542f93a6f55",
            "225747f3b5d5dab4e5a424f81f85c904ff43286e0f3fd07ef0b8c6a627b11458",
            "7c3ea01a6e3a3d90cf59cd789e467044b5cd78eb2c84cc6816f960746d0e036c",
            "50421d6c2c94571dfaaa135a4ff15bf916681ebd62c0e43e69e3b90684d0a030",
            "aaec63863aaa0b2e3b8009429bdddd455e59be6f40ccab887a32eb98723efc12",
            "f76748d40d5ee5f9a608512e7954dd515f86e8f6d009141c89163de1cf351a02",
            "bc8a5ec71647415c380203b681f7717366f3501661512225b6dc3e121efc0b2e",
            "da1adda2ccde9381e11151686c121e7f52d19a990439161c7eb5a9f94be5a511",
            "3a27fed5dbbc475d3880360e38638c882fd9b273b618fc433106896083f77446",
            "c7ca8f7df8fd997931d33985d935ee2d696856cc09cc516d419ea6365f163008",
            "f0fa37e8063b139d342246142fc48e7c0c50d0a62c97768589e06466742c3702",
            "e6d4d7685894d01b32f7e081ab188930be6c2b9f76d6847b7f382e3dddd7c608",
            "8cebb73be883466d18d3b0c06990520e80b936440a2c9fd184d92a1f06c4e826",
            "22fab8bcdb88154dbf5877ad1e2d7f1b541bc8a5ec1b52266095381339c27c03",
            "f43e3aac61e5a753062d4d0508c26ceaf5e4c0c58ba3c956e104b5d2cf67c41c",
            "3a3661bc12b72646c94bc6c92796e81953985ee62d80a9ec3645a9a95740ac15",
        ];
        for right in 8..16 {
            let mut orig = CommitmentTree::empty();
            let mut cmus = Vec::new();
            let mut paths: Vec<IncrementalWitness<Node>> = Vec::new();
            for commitment in commitments.iter().take(right) {
                let cmu = hex::decode(commitment).unwrap();
                let cmu = Node::new(cmu[..].try_into().unwrap());
                orig.append(cmu).unwrap();
                cmus.push(cmu);
                for path in &mut paths {
                    path.append(cmu).unwrap();
                }
                paths.push(IncrementalWitness::from_tree(&orig));
            }
            let frozen1 = FrozenCommitmentTree::new(&cmus[0..8]);
            let frozen2 = FrozenCommitmentTree::new(&cmus[8..right]);
            let frozen = FrozenCommitmentTree::merge(&[frozen1, frozen2]);
            assert_eq!(orig.root(), frozen.root());
            for (i, path) in paths.iter().enumerate() {
                let path = path.path().unwrap();
                assert_eq!(path.auth_path, frozen.path(i).auth_path);
                assert_eq!(path.position, frozen.path(i).position);
            }
        }
    }

    #[test]
    fn empty_root_test_vectors() {
        let mut prev = Node::blank();
        assert_eq!(Node::empty_root(0), prev);
        for i in 1..=32 {
            let next = Node::combine(i - 1, &prev, &prev);
            assert_eq!(Node::empty_root(i), next);
            prev = next;
        }
    }

    #[test]
    fn sapling_empty_root() {
        assert_eq!(
            CommitmentTree::<Node>::empty().root(),
            Node::empty_root(SAPLING_COMMITMENT_TREE_DEPTH)
        );
    }

    #[test]
    fn empty_commitment_tree_roots() {
        let tree = CommitmentTree::<Node>::empty();
        for i in 1..=SAPLING_COMMITMENT_TREE_DEPTH {
            assert_eq!(tree.root_inner(i, PathFiller::empty()), Node::empty_root(i));
        }
    }

    #[test]
    fn test_poseidon_merkle_fixtures() {
        fn parse_hex_32(value: &str) -> [u8; 32] {
            hex::decode(value)
                .unwrap()
                .try_into()
                .expect("fixture hex must decode to 32 bytes")
        }

        let fixture: Value = serde_json::from_str(crate::test_vectors::POSEIDON_FIXTURES_JSON)
            .expect("poseidon fixture JSON must parse");

        let empty_roots = fixture["empty_roots"]
            .as_array()
            .expect("empty_roots must be an array");
        assert_eq!(empty_roots.len(), SAPLING_COMMITMENT_TREE_DEPTH + 1);

        for (depth, expected_hex) in empty_roots.iter().enumerate() {
            let expected = parse_hex_32(expected_hex.as_str().expect("root hex must be a string"));
            assert_eq!(Node::empty_root(depth).into_repr(), expected);
        }

        let parent_cases = fixture["parent_cases"]
            .as_array()
            .expect("parent_cases must be an array");
        for case in parent_cases {
            let depth = case["depth"].as_u64().expect("depth must be u64") as usize;
            let left = bls12_381::Scalar::from_repr(parse_hex_32(
                case["left"].as_str().expect("left must be string"),
            ))
            .unwrap();
            let right = bls12_381::Scalar::from_repr(parse_hex_32(
                case["right"].as_str().expect("right must be string"),
            ))
            .unwrap();
            let expected = parse_hex_32(case["result"].as_str().expect("result must be string"));

            let actual = Node::combine(depth, &Node::from_scalar(left), &Node::from_scalar(right));
            assert_eq!(actual.into_repr(), expected);
        }
    }

    proptest! {
        #[test]
        fn prop_commitment_tree_roundtrip(ct in arb_commitment_tree(32, arb_node(), 8)) {
            let ct_inc = ct.clone().into_incrementalmerkletree();
            let ct0 = CommitmentTree::from_incrementalmerkletree(&ct_inc);
            assert_eq!(ct.size(), ct0.size());
            assert_eq!(ct.root(), ct0.root());
        }
    }

    #[test]
    fn test_commitment_tree_complete() {
        let mut t: CommitmentTree<TestNode> = CommitmentTree::empty();
        for n in 1u64..=32 {
            t.append(TestNode(n)).unwrap();
            // every tree of a power-of-two height is complete
            let is_complete = n.count_ones() == 1;
            let level = 63 - n.leading_zeros(); //log2
            assert_eq!(
                is_complete,
                t.is_complete(level.try_into().unwrap()),
                "Tree {:?} {} complete at height {}",
                t,
                if is_complete {
                    "should be"
                } else {
                    "should not be"
                },
                n
            );
        }
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
    use core::fmt::Debug;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    use std::io::{self, Read, Write};

    use super::{CommitmentTree, Hashable};

    pub fn arb_commitment_tree<Node: Hashable + Debug, T: Strategy<Value = Node>>(
        min_size: usize,
        arb_node: T,
        depth: u8,
    ) -> impl Strategy<Value = CommitmentTree<Node>> {
        assert!((1 << depth) >= min_size + 100);
        vec(arb_node, min_size..(min_size + 100)).prop_map(move |v| {
            let mut tree = CommitmentTree::empty();
            for node in v.into_iter() {
                tree.append(node).unwrap();
            }
            tree.parents.resize_with((depth - 1).into(), || None);
            tree
        })
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) struct TestNode(pub(crate) u64);

    impl Hashable for TestNode {
        fn read<R: Read>(mut reader: R) -> io::Result<TestNode> {
            reader.read_u64::<LittleEndian>().map(TestNode)
        }

        fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
            writer.write_u64::<LittleEndian>(self.0)
        }

        fn combine(_: usize, a: &TestNode, b: &TestNode) -> TestNode {
            let mut hasher = DefaultHasher::new();
            hasher.write_u64(a.0);
            hasher.write_u64(b.0);
            TestNode(hasher.finish())
        }

        fn blank() -> TestNode {
            TestNode(0)
        }

        fn empty_root(alt: usize) -> TestNode {
            (0..alt).fold(Self::blank(), |v, lvl| Self::combine(lvl, &v, &v))
        }
    }
}
