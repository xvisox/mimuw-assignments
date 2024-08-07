module Graph where
import Set(Set)
import qualified Set as Set
import qualified Data.List

class Graph g where
  empty   :: g a
  vertex  :: a -> g a
  union   :: g a -> g a -> g a
  connect :: g a -> g a -> g a

data Relation a = Relation { domain :: Set a, relation :: Set (a, a) }
    deriving (Eq, Show)

data Basic a = Empty
             | Vertex a
             | Union (Basic a) (Basic a)
             | Connect (Basic a) (Basic a)

instance Graph Relation where
  empty         = Relation {domain = Set.empty, relation = Set.empty}
  vertex el     = Relation {domain = Set.singleton el, relation = Set.empty}
  union g1 g2   = Relation {domain = newDomain, relation = newRelation} where
    newDomain   = domain g1 <> domain g2
    newRelation = relation g1 <> relation g2
  connect g1 g2 = Relation { domain = newDomain, relation = newRelation } where
    newDomain   = domain g1 <> domain g2
    newRelation = relation g1 <> relation g2 <> crossProduct (domain g1) (domain g2)
    crossProduct d1 d2 = Set.fromList [(x, y) | x <- Set.toList d1, y <- Set.toList d2]

instance (Ord a, Num a) => Num (Relation a) where
  fromInteger = vertex . fromInteger
  (+)         = union
  (*)         = connect
  signum      = const empty
  abs         = id
  negate      = id

instance Graph Basic where
  empty = Empty
  vertex = Vertex
  union = auxUnion where
    auxUnion Empty graph   = graph
    auxUnion graph Empty   = graph
    auxUnion graph1 graph2 = Union graph1 graph2
  connect = auxConnect where
    auxConnect Empty graph   = graph
    auxConnect graph Empty   = graph
    auxConnect graph1 graph2 = Connect graph1 graph2

instance Ord a => Eq (Basic a) where
  graph1 == graph2 = graphRelation1 == graphRelation2 where
    graphRelation1 = (fromBasic :: Basic a -> Relation a) graph1
    graphRelation2 = (fromBasic :: Basic a -> Relation a) graph2

instance (Ord a, Num a) => Num (Basic a) where
    fromInteger = vertex . fromInteger
    (+)         = union
    (*)         = connect
    signum      = const empty
    abs         = id
    negate      = id

instance Semigroup (Basic a) where
  (<>) = union

instance Monoid (Basic a) where
  mempty = Empty

fromBasic :: Graph g => Basic a -> g a
fromBasic Empty                   = empty
fromBasic (Vertex el)             = vertex el
fromBasic (Union graph1 graph2)   = union (fromBasic graph1) (fromBasic graph2)
fromBasic (Connect graph1 graph2) = connect (fromBasic graph1) (fromBasic graph2)

instance (Ord a, Show a) => Show (Basic a) where
  show graph        = showsPrec 0 graph ""
  showsPrec _ graph = showString "edges " . showList edges . showString " + vertices " . showList isolatedVertices where
    (edges, isolatedVertices) = getEdgesAndIsolatedVertices graph

-- | Example graph
-- >>> example34
-- edges [(1,2),(2,3),(2,4),(3,5),(4,5)] + vertices [17]

example34 :: Basic Int
example34 = 1*2 + 2*(3+4) + (3+4)*5 + 17

todot :: (Ord a, Show a) => Basic a -> String
todot graph = showsTodot "" where
  (edges, isolatedVertices) = getEdgesAndIsolatedVertices graph

  showsTodot :: ShowS
  showsTodot = showString "digraph {\n" . showsEdges edges . showsIsolatedVertices isolatedVertices . showString "}" where
    showsEdges :: (Ord a, Show a) => [(a,a)] -> ShowS
    showsEdges [] = id
    showsEdges ((x,y):xs) = (showsPrec 0 x) . showString " -> " . (showsPrec 0 y) . showString ";\n" . showsEdges xs

    showsIsolatedVertices :: (Ord a, Show a) => [a] -> ShowS
    showsIsolatedVertices [] = id
    showsIsolatedVertices (x:xs) = (showsPrec 0 x) . showString ";\n" . showsIsolatedVertices xs

instance Functor Basic where
  fmap _ Empty                   = empty
  fmap f (Vertex el)             = vertex (f el)
  fmap f (Union graph1 graph2)   = union (f <$> graph1) (f <$> graph2)
  fmap f (Connect graph1 graph2) = connect (f <$> graph1) (f <$> graph2)

-- | Merge vertices
-- >>> mergeV 3 4 34 example34
-- edges [(1,2),(2,34),(34,5)] + vertices [17]

mergeV :: Eq a => a -> a -> a -> Basic a -> Basic a
mergeV prev1 prev2 curr graph = auxMerge <$> graph where
  auxMerge v
    | v == prev1 = curr
    | v == prev2 = curr
    | otherwise  = v

instance Applicative Basic where
  pure                      = vertex
  Empty           <*> _     = empty
  (Vertex f)      <*> graph = f <$> graph
  (Union f1 f2)   <*> graph = union (f1 <*> graph) (f2 <*> graph)
  (Connect f1 f2) <*> graph = connect (f1 <*> graph) (f2 <*> graph)

instance Monad Basic where
  Empty                   >>= _ = Empty
  (Vertex el)             >>= f = f el
  (Union graph1 graph2)   >>= f = union (graph1 >>= f) (graph2 >>= f)
  (Connect graph1 graph2) >>= f = connect (graph1 >>= f) (graph2 >>= f)

-- | Split Vertex
-- >>> splitV 34 3 4 (mergeV 3 4 34 example34)
-- edges [(1,2),(2,3),(2,4),(3,5),(4,5)] + vertices [17]

splitV :: Eq a => a -> a -> a -> Basic a -> Basic a
splitV prev curr1 curr2 graph = graph >>= auxSplit where
  auxSplit v
    | v == prev = (return curr1) <> (return curr2)
    | otherwise = return v

getEdgesAndIsolatedVertices :: Ord a => Basic a -> ([(a,a)], [a])
getEdgesAndIsolatedVertices basicGraph = (edges, isolatedVertices) where
  edges            = Set.toAscList (relation relationGraph)
  isolatedVertices = diffOrd domainVertices edgesVertices where
    diffOrd :: Ord a => [a] -> [a] -> [a]
    diffOrd [] _ = []
    diffOrd xs [] = xs
    diffOrd (x:xs) (y:ys)
      | x < y     = x : diffOrd xs (y:ys)
      | x == y    = diffOrd xs ys
      | otherwise = diffOrd (x:xs) ys

  relationGraph  = (fromBasic :: Basic a -> Relation a) basicGraph
  domainVertices = Set.toAscList $ domain relationGraph
  edgesVertices  = nubOrd $ Data.List.sort $ concatMap (\(x, y) -> [x, y]) edges where
    nubOrd :: Ord a => [a] -> [a]
    nubOrd [] = []
    nubOrd [x] = [x]
    nubOrd (x:y:zs)
      | x == y    = nubOrd (y:zs)
      | otherwise = x : nubOrd (y:zs)
