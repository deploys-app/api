// Code generated by "stringer -type=DeploymentAction -linecomment"; DO NOT EDIT.

package api

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[DeploymentActionDeploy-1]
	_ = x[DeploymentActionDelete-2]
	_ = x[DeploymentActionPause-3]
}

const _DeploymentAction_name = "deploydeletepause"

var _DeploymentAction_index = [...]uint8{0, 6, 12, 17}

func (i DeploymentAction) String() string {
	i -= 1
	if i < 0 || i >= DeploymentAction(len(_DeploymentAction_index)-1) {
		return "DeploymentAction(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _DeploymentAction_name[_DeploymentAction_index[i]:_DeploymentAction_index[i+1]]
}
