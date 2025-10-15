package webexposure

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/projectdiscovery/dsl"
	nucleidsl "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

// init registers custom DSL functions globally before any other package initialization
// This MUST run before nuclei package is initialized to ensure custom functions are available
func init() {
	logger := GetLogger()

	// Register to_value_group function: to_value_group(key, values...) -> <f><k>key</k><vg><v>base64(val)</v>...</vg></f>
	err := dsl.AddFunction(dsl.NewWithPositionalArgs(
		"to_value_group",
		-1,    // Accept variable number of arguments
		false, // Not cacheable
		func(args ...interface{}) (interface{}, error) {
			if len(args) < 1 {
				GetLogger().Debug().Msg("to_value_group called with no key, returning empty")
				return "", nil // Empty result if no key provided
			}

			// First argument is the key
			key := fmt.Sprintf("%v", args[0])

			// Remaining arguments are values
			values := args[1:]

			// If no values provided, return empty
			if len(values) == 0 {
				GetLogger().Debug().Msgf("to_value_group called with key '%s' but no values, returning empty", key)
				return "", nil
			}

			// Key is NOT base64 encoded - only values are encoded
			// Build value group with base64 encoded values
			var vgroup strings.Builder
			vgroup.WriteString("<vg>")

			for _, val := range values {
				// Handle different value types
				var strVal string

				// Check if val is a slice/array
				valReflect := reflect.ValueOf(val)
				if valReflect.Kind() == reflect.Slice || valReflect.Kind() == reflect.Array {
					// If it's an array, iterate over elements
					for i := 0; i < valReflect.Len(); i++ {
						elem := valReflect.Index(i)
						elemStr := fmt.Sprintf("%v", elem.Interface())
						if elemStr != "" {
							encodedVal := base64.StdEncoding.EncodeToString([]byte(elemStr))
							vgroup.WriteString("<v>")
							vgroup.WriteString(encodedVal)
							vgroup.WriteString("</v>")
						}
					}
					continue
				}

				// For non-array values, convert to string
				strVal = fmt.Sprintf("%v", val)
				if strVal != "" {
					encodedVal := base64.StdEncoding.EncodeToString([]byte(strVal))
					vgroup.WriteString("<v>")
					vgroup.WriteString(encodedVal)
					vgroup.WriteString("</v>")
				}
			}

			vgroup.WriteString("</vg>")

			// Return complete finding structure - key is plain text, values are base64
			result := fmt.Sprintf("<f><k>%s</k>%s</f>", key, vgroup.String())
			GetLogger().Debug().Msgf("to_value_group: generated finding for key '%s' with %d values", key, len(values))
			return result, nil
		},
	))

	if err != nil {
		logger.Error().Msgf("Failed to register DSL function to_value_group: %v", err)
	} else {
		logger.Debug().Msg("Registered custom DSL function: to_value_group")
	}

	// Update Nuclei's HelperFunctions to include our custom function
	// This is what Nuclei uses when compiling DSL expressions in templates
	nucleidsl.HelperFunctions = dsl.HelperFunctions()
	nucleidsl.FunctionNames = dsl.GetFunctionNames(nucleidsl.HelperFunctions)
}
