package sessionup

import "context"

type Store interface {
	Create(ctx context.Context, ses Session) error
	FetchByToken(ctx context.Context, tok string) (Session, error)
	FetchByUserKey(ctx context.Context, key string) ([]Session, error)
	DeleteByToken(ctx context.Context, tok string) error
	DeleteByUserKey(ctx context.Context, key string, expTok ...string) error
}
