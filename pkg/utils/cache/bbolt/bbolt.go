package bbolt

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"go.etcd.io/bbolt"
)

type Cache struct {
	db *bbolt.DB

	bucketName [][]byte
}

func NewCache(db *bbolt.DB, bucketName string) *Cache {
	c := &Cache{
		db:         db,
		bucketName: [][]byte{[]byte(bucketName)},
	}

	return c
}

func (c *Cache) Get(k []byte) (v []byte, err error) {
	if c.db == nil {
		return nil, nil
	}

	err = c.db.View(func(tx *bbolt.Tx) error {
		bk := c.existBucket(tx)
		if bk == nil {
			return nil
		}

		vv := bk.Get(k)
		if vv != nil {
			v = make([]byte, len(vv))
			copy(v, vv)
		}
		return nil
	})

	return v, err
}

func (c *Cache) existBucket(tx *bbolt.Tx) *bbolt.Bucket {
	bk := tx.Bucket(c.bucketName[0])
	if bk == nil {
		return nil
	}

	for _, v := range c.bucketName[1:] {
		bk = bk.Bucket(v)
		if bk == nil {
			return nil
		}
	}

	return bk
}

func (c *Cache) bucket(tx *bbolt.Tx) (*bbolt.Bucket, error) {
	bk := tx.Bucket(c.bucketName[0])
	if bk == nil {
		var err error
		bk, err = tx.CreateBucketIfNotExists(c.bucketName[0])
		if err != nil {
			return nil, err
		}
	}

	for _, v := range c.bucketName[1:] {
		x := bk.Bucket(v)
		if x == nil {
			var err error
			x, err = bk.CreateBucketIfNotExists(v)
			if err != nil {
				return nil, err
			}
		}

		bk = x
	}

	return bk, nil
}

func (c *Cache) Put(k, v []byte) error {
	if c.db == nil {
		return nil
	}

	return c.db.Batch(func(tx *bbolt.Tx) error {
		bk, err := c.bucket(tx)
		if err != nil {
			return err
		}
		return bk.Put(k, v)
	})
}

func (c *Cache) Delete(k ...[]byte) error {
	if c.db == nil {
		return nil
	}

	return c.db.Batch(func(tx *bbolt.Tx) error {
		bk := c.existBucket(tx)
		if bk == nil {
			return nil
		}

		for _, kk := range k {
			if kk == nil {
				continue
			}

			if err := bk.Delete(kk); err != nil {
				return err
			}
		}

		return nil
	})
}

func (c *Cache) Range(f func(key []byte, value []byte) bool) error {
	if c.db == nil {
		return nil
	}

	return c.db.View(func(tx *bbolt.Tx) error {
		bkt, err := c.bucket(tx)
		if err != nil {
			return err
		}

		_ = bkt.ForEach(func(k, v []byte) error {
			if !f(k, v) {
				return errors.New("break")
			}
			return nil
		})

		return nil
	})
}

func (c *Cache) Close() error {
	return nil
}

func (c *Cache) NewCache(str string) cache.Cache {
	return &Cache{
		db:         c.db,
		bucketName: append(c.bucketName, []byte(str)),
	}
}
