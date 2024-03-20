module Set(Set(..), empty, null, singleton, union, fromList
              , member, toList, toAscList, elems
              ) where
import Prelude hiding(null)
import qualified Data.List

data Set a = Empty
           | Singleton a
           | Union (Set a) (Set a)

empty :: Set a
empty = Empty

null :: Set a -> Bool
null Empty = True
null _ = False

member :: Eq a => a -> Set a -> Bool
member _ Empty = False
member el (Singleton val) = el == val
member el (Union set1 set2) = member el set1 || member el set2

singleton :: a -> Set a
singleton = Singleton

fromList :: [a] -> Set a
fromList = foldr insert empty

toList :: Set a -> [a]
toList set = toListAcc set [] where
  toListAcc :: Set a -> [a] -> [a]
  toListAcc Empty acc = acc
  toListAcc (Singleton el) acc = el : acc
  toListAcc (Union set1 set2) acc = toListAcc set1 (toListAcc set2 acc)

toAscList :: Ord a => Set a -> [a]
toAscList = nubOrd . Data.List.sort . toList where
  nubOrd :: Ord a => [a] -> [a]
  nubOrd [] = []
  nubOrd [x] = [x]
  nubOrd (x:y:zs)
    | x == y    = nubOrd (y:zs)
    | otherwise = x : nubOrd (y:zs)

elems :: Set a -> [a]
elems = toList

union :: Set a -> Set a -> Set a
union Empty set = set;
union set Empty = set;
union set1 set2 = Union set1 set2

insert :: a -> Set a -> Set a
insert el = union (singleton el)

instance Ord a => Eq (Set a) where
  set1 == set2 = toAscList set1 == toAscList set2

instance Semigroup (Set a) where
  (<>) = union

instance Monoid (Set a) where
  mempty = empty

instance Show a => Show (Set a) where
  show = show . toList

instance Functor Set where
  fmap _ Empty = empty
  fmap f (Singleton el) = singleton (f el)
  fmap f (Union set1 set2) = (f <$> set1) <> (f <$> set2)
