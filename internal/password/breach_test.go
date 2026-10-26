package password

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

type fakeChecker struct {
	breached bool
	err      error
}

func (f fakeChecker) IsBreached(context.Context, string) (bool, error) { return f.breached, f.err }

type spyAudit struct{ types []string }

func (s *spyAudit) LogEvent(_ context.Context, e audit.Event) { s.types = append(s.types, e.Type) }

func TestCheckNotBreached(t *testing.T) {
	tests := []struct {
		name      string
		checker   fakeChecker
		nilCheck  bool
		wantErr   error
		wantEvent string
	}{
		{name: "nil checker disables check", nilCheck: true},
		{name: "not breached", checker: fakeChecker{}},
		{name: "breached", checker: fakeChecker{breached: true}, wantErr: domain.ErrPasswordBreached, wantEvent: audit.EventPasswordBreached},
		{name: "error fails open", checker: fakeChecker{err: errors.New("boom")}, wantEvent: audit.EventBreachCheckFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &spyAudit{}
			var err error
			if tt.nilCheck {
				err = CheckNotBreached(context.Background(), nil, zap.NewNop(), spy, "", "test", "pw")
			} else {
				err = CheckNotBreached(context.Background(), tt.checker, zap.NewNop(), spy, "u1", "test", "pw")
			}
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			if tt.wantEvent == "" {
				assert.Empty(t, spy.types)
			} else {
				assert.Equal(t, []string{tt.wantEvent}, spy.types)
			}
		})
	}
}
