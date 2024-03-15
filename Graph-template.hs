module Graph where
import Set(Set)
import qualified Set as Set

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
todot graph = showsTodot graph "" where
  (edges, isolatedVertices) = getEdgesAndIsolatedVertices graph

  showsTodot :: (Ord a, Show a) => Basic a -> ShowS
  showsTodot graph = showString "digraph {" . showsEdges edges . showsIsolatedVertices isolatedVertices . showString "}" where
    showsEdges :: (Ord a, Show a) => [(a,a)] -> ShowS
    showsEdges [] = id
    showsEdges ((x,y):xs) = (showsPrec 0 x) . showString " -> " . (showsPrec 0 y) . showString "; " . showsEdges xs

    showsIsolatedVertices :: (Ord a, Show a) => [a] -> ShowS
    showsIsolatedVertices [] = id
    showsIsolatedVertices (x:xs) = (showsPrec 0 x) . showString "; " . showsIsolatedVertices xs

instance Functor Basic where
  fmap f Empty                   = empty
  fmap f (Vertex el)             = vertex (f el)
  fmap f (Union graph1 graph2)   = union (f <$> graph1) (f <$> graph2)
  fmap f (Connect graph1 graph2) = connect (f <$> graph1) (f <$> graph2)

-- | Merge vertices
-- >>> mergeV 3 4 34 example34
-- edges [(1,2),(2,34),(34,5)] + vertices [17]

mergeV :: Eq a => a -> a -> a -> Basic a -> Basic a
mergeV prev1 prev2 curr graph = (\v -> if v == prev1 || v == prev2 then curr else v) <$> graph

instance Applicative Basic where

instance Monad Basic where

-- | Split Vertex
-- >>> splitV 34 3 4 (mergeV 3 4 34 example34)
-- edges [(1,2),(2,3),(2,4),(3,5),(4,5)] + vertices [17]

splitV :: Eq a => a -> a -> a -> Basic a -> Basic a
splitV = undefined

getEdgesAndIsolatedVertices :: Ord a => Basic a -> ([(a,a)], [a])
getEdgesAndIsolatedVertices basicGraph = (edges, isolatedVertices) where
  edges            = Set.toAscList (relation relationGraph)
  isolatedVertices = diff domainVertices edgesVertices where
    diff :: Ord a => [a] -> [a] -> [a]
    diff [] _ = []
    diff xs [] = xs
    diff (x:xs) (y:ys)
      | x < y     = x : diff xs (y:ys)
      | x == y    = diff xs ys
      | otherwise = diff (x:xs) ys

  relationGraph  = (fromBasic :: Basic a -> Relation a) basicGraph
  domainVertices = domain relationGraph
  edgesVertices  = nubOrd $ sort $ concatMap (\(x, y) -> [x, y]) edges where
    nubOrd :: Ord a => [a] -> [a]
    nubOrd [] = []
    nubOrd [x] = [x]
    nubOrd (x:y:zs)
      | x == y    = nubOrd (y:zs)
      | otherwise = x : nubOrd (y:zs)
