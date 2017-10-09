module Data.Multihash.Digest where

import qualified Crypto.Hash                as CH
import qualified Crypto.Hash.Algorithms     as HA

import           Control.Applicative        ((<$>))
import           Data.Attoparsec.ByteString (Parser, parseOnly)
import qualified Data.Attoparsec.ByteString as A
import qualified Data.ByteArray             as BA
import qualified Data.ByteString            as BS
import           Data.ByteString.Builder    (Builder, byteString,
                                             toLazyByteString)
import qualified Data.ByteString.Builder    as BB
import qualified Data.ByteString.Lazy       as BL
import           Data.Monoid                ((<>))

import           System.IO.Streams          (InputStream)
import           System.IO.Streams.Crypto   (hashInputStream)

data MultihashDigest =
    MultihashDigest
    { algorithm :: !HashAlgorithm
    , length    :: !Length
    , digest    :: !Digest
    } deriving (Show, Eq)


type Length = Int
type Digest = BS.ByteString


data HashAlgorithm
    = SHA1
    | SHA256
    | SHA512
    | SHA3_512
    | SHA3_384
    | SHA3_256
    | SHA3_224
    deriving (Show, Read, Eq, Enum, Bounded)


multihash :: HashAlgorithm -> BS.ByteString -> MultihashDigest
multihash ha bs = MultihashDigest ha (BS.length digest') digest'
  where
    digest' = hash ha bs


hash :: HashAlgorithm -> BS.ByteString -> Digest
hash SHA1     = BA.convert . CH.hashWith HA.SHA1
hash SHA256   = BA.convert . CH.hashWith HA.SHA256
hash SHA512   = BA.convert . CH.hashWith HA.SHA512
hash SHA3_512 = BA.convert . CH.hashWith HA.SHA3_512
hash SHA3_384 = BA.convert . CH.hashWith HA.SHA3_384
hash SHA3_256 = BA.convert . CH.hashWith HA.SHA3_256
hash SHA3_224 = BA.convert . CH.hashWith HA.SHA3_224


-- TODO add BLAKE support
hashStream :: HashAlgorithm -> InputStream BS.ByteString -> IO Digest
hashStream SHA1     is = BA.convert <$> (hashInputStream is :: IO (CH.Digest CH.SHA1))
hashStream SHA256   is = BA.convert <$> (hashInputStream is :: IO (CH.Digest CH.SHA256))
hashStream SHA512   is = BA.convert <$> (hashInputStream is :: IO (CH.Digest CH.SHA512))
hashStream SHA3_512 is = BA.convert <$> (hashInputStream is :: IO (CH.Digest CH.SHA3_512))
hashStream SHA3_384 is = BA.convert <$> (hashInputStream is :: IO (CH.Digest CH.SHA3_384))
hashStream SHA3_256 is = BA.convert <$> (hashInputStream is :: IO (CH.Digest CH.SHA3_256))
hashStream SHA3_224 is = BA.convert <$> (hashInputStream is :: IO (CH.Digest CH.SHA3_224))


fromCode :: Int -> HashAlgorithm
fromCode 0x11 = SHA1
fromCode 0x12 = SHA256
fromCode 0x13 = SHA512
fromCode 0x14 = SHA3_512
fromCode 0x15 = SHA3_384
fromCode 0x16 = SHA3_256
fromCode 0x17 = SHA3_224
-- fromCode 0x40 = BLAKE2B
-- fromCode 0x41 = BLAKE2S
fromCode _    = error "Unknown hash function code"


toCode :: HashAlgorithm -> Int
toCode SHA1     = 0x11
toCode SHA256   = 0x12
toCode SHA512   = 0x13
toCode SHA3_512 = 0x14
toCode SHA3_384 = 0x15
toCode SHA3_256 = 0x16
toCode SHA3_224 = 0x17
-- toCode BLAKE2B  = 0x40
-- toCode BLAKE2S  = 0x41


encode :: HashAlgorithm -> Digest -> BL.ByteString
encode h d = toLazyByteString $ encoder h d


encoder :: HashAlgorithm -> Digest -> Builder
encoder h d
    =  (BB.word8 . fromIntegral $ toCode h)
    <> (BB.word8 . fromIntegral $ BS.length d)
    <> byteString d

encodeMultihashDigest :: MultihashDigest -> BL.ByteString
encodeMultihashDigest mhd = encode (algorithm mhd) (digest mhd)

decode :: BS.ByteString -> Either String MultihashDigest
decode = parseOnly decoder


decoder :: Parser MultihashDigest
decoder = do
    h <- (fromCode . fromIntegral <$> A.anyWord8)
    l <- (fromIntegral <$> A.anyWord8)
    d <- A.take l
    return $ MultihashDigest h l d
