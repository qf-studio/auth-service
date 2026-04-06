package grpc

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const metadataKeyRequestID = "x-request-id"

type loggerKey struct{}

// LoggerFromContext retrieves the per-request logger stored by the logging interceptor.
func LoggerFromContext(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*zap.Logger); ok {
		return l
	}
	return nil
}

// UnaryLoggingInterceptor returns a unary server interceptor that:
//   - extracts or generates a correlation ID (x-request-id) from gRPC metadata,
//   - creates a child logger with the request_id field,
//   - logs the method, duration, and status code of every call.
func UnaryLoggingInterceptor(base *zap.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		requestID := extractOrGenerateRequestID(ctx)
		reqLogger := base.With(
			zap.String("request_id", requestID),
			zap.String("grpc.method", info.FullMethod),
		)
		ctx = context.WithValue(ctx, loggerKey{}, reqLogger)
		ctx = metadata.AppendToOutgoingContext(ctx, metadataKeyRequestID, requestID)

		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		code := status.Code(err)
		reqLogger.Info("grpc unary call",
			zap.String("grpc.code", code.String()),
			zap.Duration("grpc.duration", duration),
		)

		return resp, err
	}
}

// StreamLoggingInterceptor returns a stream server interceptor that mirrors
// the unary interceptor: correlation ID propagation and per-stream logging.
func StreamLoggingInterceptor(base *zap.Logger) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()
		requestID := extractOrGenerateRequestID(ctx)
		reqLogger := base.With(
			zap.String("request_id", requestID),
			zap.String("grpc.method", info.FullMethod),
		)
		ctx = context.WithValue(ctx, loggerKey{}, reqLogger)

		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}

		start := time.Now()
		err := handler(srv, wrapped)
		duration := time.Since(start)

		code := status.Code(err)
		reqLogger.Info("grpc stream call",
			zap.String("grpc.code", code.String()),
			zap.Duration("grpc.duration", duration),
		)

		return err
	}
}

// UnaryMetricsInterceptor returns a unary server interceptor that records
// method, status code, and duration for every call.
func UnaryMetricsInterceptor(recorder MetricsRecorder) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		recorder.RecordGRPCRequest(info.FullMethod, status.Code(err).String(), time.Since(start))
		return resp, err
	}
}

// StreamMetricsInterceptor returns a stream server interceptor that records
// method, status code, and duration for every stream.
func StreamMetricsInterceptor(recorder MetricsRecorder) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		start := time.Now()
		err := handler(srv, ss)
		recorder.RecordGRPCRequest(info.FullMethod, status.Code(err).String(), time.Since(start))
		return err
	}
}

// MetricsRecorder is the interface for recording gRPC request metrics.
type MetricsRecorder interface {
	RecordGRPCRequest(method, code string, duration time.Duration)
}

// extractOrGenerateRequestID reads x-request-id from incoming gRPC metadata.
// If absent, it generates a new UUID v4.
func extractOrGenerateRequestID(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(metadataKeyRequestID); len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return uuid.NewString()
}

// wrappedServerStream overrides Context() to carry the enriched context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
