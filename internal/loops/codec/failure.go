package codec

import (
	failurepb "go.temporal.io/api/failure/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
)

// notEncodable is the message of a failure whose sealing failed (D6).
const notEncodable = "rempart: failure not encodable"

// failureConverter seals message, stack trace and details with the converter
// of the process; it never panics and never falls back to clear (D6).
type failureConverter struct {
	dc    *dataConverter
	inner converter.FailureConverter
}

// NewFailureConverter returns the failure converter over dc, which must come
// from NewDataConverter (ErrNotRempart otherwise).
func NewFailureConverter(dc converter.DataConverter) (converter.FailureConverter, error) {
	c, ok := dc.(*dataConverter)
	if !ok || c == nil || c.bindErr != nil {
		return nil, ErrNotRempart
	}
	return &failureConverter{dc: c, inner: temporal.NewDefaultFailureConverter(temporal.DefaultFailureConverterOptions{
		DataConverter: c, EncodeCommonAttributes: true,
	})}, nil
}

func (f *failureConverter) ErrorToFailure(err error) (out *failurepb.Failure) {
	defer func() {
		if recover() != nil {
			out = &failurepb.Failure{
				Message: notEncodable,
				Source:  "GoSDK",
				FailureInfo: &failurepb.Failure_ApplicationFailureInfo{
					ApplicationFailureInfo: &failurepb.ApplicationFailureInfo{Type: ErrTypeNotEncodable},
				},
			}
		}
	}()
	return f.inner.ErrorToFailure(err)
}

func (f *failureConverter) FailureToError(failure *failurepb.Failure) error {
	return f.inner.FailureToError(failure)
}
