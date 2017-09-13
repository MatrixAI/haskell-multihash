module System.IO.Streams.Crypto where

import           Crypto.Hash            (Digest, hashInit, hashFinalize, 
                                         hashUpdates)
import           Crypto.Hash.Algorithms (HashAlgorithm)
import           Data.ByteString        (ByteString)
import           System.IO.Streams      (InputStream, fold)

hashInputStream :: (HashAlgorithm h) => InputStream ByteString -> IO (Digest h)
hashInputStream = fmap hashFinalize . fold update hashInit
  where update ctx bs = hashUpdates ctx [bs]
