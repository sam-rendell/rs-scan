package targets

// IntervalNode represents a node in an AVL-balanced Interval Tree.
type IntervalNode struct {
	Start       uint32
	End         uint32
	MaxEnd      uint32
	Left, Right *IntervalNode
	height      int
}

// IntervalTree stores disjoint intervals and allows O(log N) lookups.
type IntervalTree struct {
	Root *IntervalNode
}

// Insert adds a range [start, end] to the tree with AVL rebalancing.
func (t *IntervalTree) Insert(start, end uint32) {
	t.Root = insertNode(t.Root, start, end)
}

func nodeHeight(n *IntervalNode) int {
	if n == nil {
		return 0
	}
	return n.height
}

func balanceFactor(n *IntervalNode) int {
	if n == nil {
		return 0
	}
	return nodeHeight(n.Left) - nodeHeight(n.Right)
}

func updateNode(n *IntervalNode) {
	lh, rh := nodeHeight(n.Left), nodeHeight(n.Right)
	if lh > rh {
		n.height = lh + 1
	} else {
		n.height = rh + 1
	}
	n.MaxEnd = n.End
	if n.Left != nil && n.Left.MaxEnd > n.MaxEnd {
		n.MaxEnd = n.Left.MaxEnd
	}
	if n.Right != nil && n.Right.MaxEnd > n.MaxEnd {
		n.MaxEnd = n.Right.MaxEnd
	}
}

func rotateRight(y *IntervalNode) *IntervalNode {
	x := y.Left
	t := x.Right
	x.Right = y
	y.Left = t
	updateNode(y)
	updateNode(x)
	return x
}

func rotateLeft(x *IntervalNode) *IntervalNode {
	y := x.Right
	t := y.Left
	y.Left = x
	x.Right = t
	updateNode(x)
	updateNode(y)
	return y
}

func insertNode(node *IntervalNode, start, end uint32) *IntervalNode {
	if node == nil {
		return &IntervalNode{Start: start, End: end, MaxEnd: end, height: 1}
	}

	if start < node.Start {
		node.Left = insertNode(node.Left, start, end)
	} else {
		node.Right = insertNode(node.Right, start, end)
	}

	updateNode(node)

	// AVL rebalancing
	bf := balanceFactor(node)
	if bf > 1 && start < node.Left.Start {
		return rotateRight(node)
	}
	if bf < -1 && start >= node.Right.Start {
		return rotateLeft(node)
	}
	if bf > 1 && start >= node.Left.Start {
		node.Left = rotateLeft(node.Left)
		return rotateRight(node)
	}
	if bf < -1 && start < node.Right.Start {
		node.Right = rotateRight(node.Right)
		return rotateLeft(node)
	}

	return node
}

// Contains checks if the value is within any interval.
// Returns (true, end_of_interval) if found, so the caller can skip ahead.
func (t *IntervalTree) Contains(val uint32) (bool, uint32) {
	return containsNode(t.Root, val)
}

func containsNode(node *IntervalNode, val uint32) (bool, uint32) {
	if node == nil {
		return false, 0
	}

	if val > node.MaxEnd {
		return false, 0
	}

	if val >= node.Start && val <= node.End {
		return true, node.End
	}

	if node.Left != nil && node.Left.MaxEnd >= val {
		found, end := containsNode(node.Left, val)
		if found {
			return true, end
		}
	}

	return containsNode(node.Right, val)
}
