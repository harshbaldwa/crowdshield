package state

import "crowdshield/internal/network"

func checkedNetworkKind(value int) (network.Kind, error) {
	switch value {
	case int(network.KindIP):
		return network.KindIP, nil
	case int(network.KindRange):
		return network.KindRange, nil
	default:
		return network.KindInvalid, stateError(ErrIntegrity, nil)
	}
}
