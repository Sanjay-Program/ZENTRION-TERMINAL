//! Recursive binary tree for arbitrary horizontal and vertical pane splits.
//!
//! Supports arbitrary tree depth, resizing (adjusting split ratios), zooming,
//! and recursive layout calculation for ratatui `Rect`s.

use ratatui::layout::Rect;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitDirection {
    /// Divides height: first child is above second child (horizontal divider).
    Horizontal,
    /// Divides width: first child is to the left of second child (vertical divider).
    Vertical,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SplitTree {
    Leaf(usize),
    Node {
        direction: SplitDirection,
        ratio: f32, // fraction of space allocated to `first` (0.1..=0.9)
        first: Box<SplitTree>,
        second: Box<SplitTree>,
    },
}

impl SplitTree {
    /// Create a single leaf representing a session index.
    pub fn new_leaf(session_idx: usize) -> Self {
        SplitTree::Leaf(session_idx)
    }

    /// Split a leaf with `target_idx` into two leaves (`target_idx` and `new_idx`)
    /// along the given `direction`.
    pub fn split_leaf(
        &mut self,
        target_idx: usize,
        new_idx: usize,
        direction: SplitDirection,
    ) -> bool {
        match self {
            SplitTree::Leaf(idx) if *idx == target_idx => {
                let first = Box::new(SplitTree::Leaf(target_idx));
                let second = Box::new(SplitTree::Leaf(new_idx));
                *self = SplitTree::Node {
                    direction,
                    ratio: 0.5,
                    first,
                    second,
                };
                true
            }
            SplitTree::Node { first, second, .. } => {
                first.split_leaf(target_idx, new_idx, direction)
                    || second.split_leaf(target_idx, new_idx, direction)
            }
            _ => false,
        }
    }

    /// Remove a leaf by session index. If found in a node, the sibling replaces the parent node.
    /// Returns true if the node was removed or pruned.
    pub fn remove_leaf(&mut self, target_idx: usize) -> bool {
        match self {
            SplitTree::Leaf(_) => false,
            SplitTree::Node { first, second, .. } => {
                if let SplitTree::Leaf(idx) = **first {
                    if idx == target_idx {
                        *self = *second.clone();
                        return true;
                    }
                }
                if let SplitTree::Leaf(idx) = **second {
                    if idx == target_idx {
                        *self = *first.clone();
                        return true;
                    }
                }

                if first.remove_leaf(target_idx) {
                    true
                } else {
                    second.remove_leaf(target_idx)
                }
            }
        }
    }

    /// When a session is removed from the tab's `Vec<Session>`, all session indices
    /// greater than `removed_idx` must be decremented by 1.
    pub fn shift_indices_after(&mut self, removed_idx: usize) {
        match self {
            SplitTree::Leaf(idx) => {
                if *idx > removed_idx {
                    *idx -= 1;
                }
            }
            SplitTree::Node { first, second, .. } => {
                first.shift_indices_after(removed_idx);
                second.shift_indices_after(removed_idx);
            }
        }
    }

    /// Adjust the ratio of the node containing the target leaf by `delta`.
    pub fn adjust_ratio(&mut self, target_idx: usize, delta: f32) -> bool {
        match self {
            SplitTree::Leaf(_) => false,
            SplitTree::Node {
                ratio,
                first,
                second,
                ..
            } => {
                let in_first = first.contains(target_idx);
                let in_second = second.contains(target_idx);
                if in_first || in_second {
                    // If target is directly inside one child, adjust this node's ratio,
                    // or recursively descend if nested deeper.
                    let nested_adjusted = if in_first {
                        first.adjust_ratio(target_idx, delta)
                    } else {
                        second.adjust_ratio(target_idx, delta)
                    };
                    if !nested_adjusted {
                        *ratio = (*ratio + delta).clamp(0.1, 0.9);
                    }
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Check if the tree contains the specified leaf index.
    pub fn contains(&self, target_idx: usize) -> bool {
        match self {
            SplitTree::Leaf(idx) => *idx == target_idx,
            SplitTree::Node { first, second, .. } => {
                first.contains(target_idx) || second.contains(target_idx)
            }
        }
    }

    /// Collect all leaf indices in tree-order.
    pub fn leaves(&self) -> Vec<usize> {
        let mut out = Vec::new();
        self.collect_leaves(&mut out);
        out
    }

    fn collect_leaves(&self, out: &mut Vec<usize>) {
        match self {
            SplitTree::Leaf(idx) => out.push(*idx),
            SplitTree::Node { first, second, .. } => {
                first.collect_leaves(out);
                second.collect_leaves(out);
            }
        }
    }

    /// Calculate the layout rectangles for all leaves in this tree.
    /// If `zoomed_leaf` is specified and matches a leaf in the tree,
    /// that leaf receives the entire `area`.
    pub fn layout(&self, area: Rect, zoomed_leaf: Option<usize>) -> Vec<(usize, Rect)> {
        if let Some(target) = zoomed_leaf {
            if self.contains(target) {
                return vec![(target, area)];
            }
        }

        let mut out = Vec::new();
        self.layout_rec(area, &mut out);
        out
    }

    fn layout_rec(&self, area: Rect, out: &mut Vec<(usize, Rect)>) {
        match self {
            SplitTree::Leaf(idx) => {
                out.push((*idx, area));
            }
            SplitTree::Node {
                direction,
                ratio,
                first,
                second,
            } => {
                let (r1, r2) = match direction {
                    SplitDirection::Horizontal => {
                        let h1 = ((area.height as f32) * ratio).round() as u16;
                        let h1 = h1.min(area.height);
                        let h2 = area.height.saturating_sub(h1);
                        (
                            Rect {
                                x: area.x,
                                y: area.y,
                                width: area.width,
                                height: h1,
                            },
                            Rect {
                                x: area.x,
                                y: area.y + h1,
                                width: area.width,
                                height: h2,
                            },
                        )
                    }
                    SplitDirection::Vertical => {
                        let w1 = ((area.width as f32) * ratio).round() as u16;
                        let w1 = w1.min(area.width);
                        let w2 = area.width.saturating_sub(w1);
                        (
                            Rect {
                                x: area.x,
                                y: area.y,
                                width: w1,
                                height: area.height,
                            },
                            Rect {
                                x: area.x + w1,
                                y: area.y,
                                width: w2,
                                height: area.height,
                            },
                        )
                    }
                };

                first.layout_rec(r1, out);
                second.layout_rec(r2, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf_layout() {
        let tree = SplitTree::new_leaf(0);
        let area = Rect::new(0, 0, 100, 50);
        let rects = tree.layout(area, None);
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0], (0, area));
    }

    #[test]
    fn test_horizontal_and_vertical_split() {
        let mut tree = SplitTree::new_leaf(0);
        assert!(tree.split_leaf(0, 1, SplitDirection::Vertical));

        let area = Rect::new(0, 0, 100, 50);
        let rects = tree.layout(area, None);
        assert_eq!(rects.len(), 2);
        assert_eq!(rects[0], (0, Rect::new(0, 0, 50, 50)));
        assert_eq!(rects[1], (1, Rect::new(50, 0, 50, 50)));

        // Split pane 1 horizontally into 1 and 2
        assert!(tree.split_leaf(1, 2, SplitDirection::Horizontal));
        let rects = tree.layout(area, None);
        assert_eq!(rects.len(), 3);
        assert_eq!(rects[0], (0, Rect::new(0, 0, 50, 50)));
        assert_eq!(rects[1], (1, Rect::new(50, 0, 50, 25)));
        assert_eq!(rects[2], (2, Rect::new(50, 25, 50, 25)));
    }

    #[test]
    fn test_zoom_mode() {
        let mut tree = SplitTree::new_leaf(0);
        tree.split_leaf(0, 1, SplitDirection::Vertical);
        tree.split_leaf(1, 2, SplitDirection::Horizontal);

        let area = Rect::new(0, 0, 100, 50);
        let zoomed = tree.layout(area, Some(2));
        assert_eq!(zoomed.len(), 1);
        assert_eq!(zoomed[0], (2, area));
    }

    #[test]
    fn test_remove_leaf_and_shift() {
        let mut tree = SplitTree::new_leaf(0);
        tree.split_leaf(0, 1, SplitDirection::Vertical);
        tree.split_leaf(1, 2, SplitDirection::Horizontal);

        // Remove pane 1
        assert!(tree.remove_leaf(1));
        // Leaves remaining: 0 and 2
        assert_eq!(tree.leaves(), vec![0, 2]);

        // Shift indices after removing session 1
        tree.shift_indices_after(1);
        assert_eq!(tree.leaves(), vec![0, 1]);
    }

    #[test]
    fn test_adjust_ratio() {
        let mut tree = SplitTree::new_leaf(0);
        tree.split_leaf(0, 1, SplitDirection::Vertical);

        tree.adjust_ratio(0, 0.1);
        let area = Rect::new(0, 0, 100, 50);
        let rects = tree.layout(area, None);
        assert_eq!(rects[0].1.width, 60);
        assert_eq!(rects[1].1.width, 40);
    }
}
