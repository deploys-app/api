package client

import (
	"context"

	"github.com/deploys-app/api"
)

type deploymentClient struct {
	inv invoker
}

func (c deploymentClient) Deploy(ctx context.Context, m *api.DeploymentDeploy) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "deployment.deploy", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) List(ctx context.Context, m *api.DeploymentList) (*api.DeploymentListResult, error) {
	var res api.DeploymentListResult
	err := c.inv.invoke(ctx, "deployment.list", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Get(ctx context.Context, m *api.DeploymentGet) (*api.DeploymentItem, error) {
	var res api.DeploymentItem
	err := c.inv.invoke(ctx, "deployment.get", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Revisions(ctx context.Context, m *api.DeploymentRevisions) (*api.DeploymentRevisionsResult, error) {
	var res api.DeploymentRevisionsResult
	err := c.inv.invoke(ctx, "deployment.revisions", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Resume(ctx context.Context, m *api.DeploymentResume) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "deployment.resume", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Pause(ctx context.Context, m *api.DeploymentPause) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "deployment.pause", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Restart(ctx context.Context, m *api.DeploymentRestart) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "deployment.restart", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Rollback(ctx context.Context, m *api.DeploymentRollback) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "deployment.rollback", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Delete(ctx context.Context, m *api.DeploymentDelete) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "deployment.delete", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Metrics(ctx context.Context, m *api.DeploymentMetrics) (*api.DeploymentMetricsResult, error) {
	var res api.DeploymentMetricsResult
	err := c.inv.invoke(ctx, "deployment.metrics", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Logs(ctx context.Context, m *api.DeploymentLogs) (*api.DeploymentLogsResult, error) {
	var res api.DeploymentLogsResult
	err := c.inv.invoke(ctx, "deployment.logs", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Status(ctx context.Context, m *api.DeploymentStatus) (*api.DeploymentStatusResult, error) {
	var res api.DeploymentStatusResult
	err := c.inv.invoke(ctx, "deployment.status", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) LogsHistory(ctx context.Context, m *api.DeploymentLogsHistory) (*api.DeploymentLogsHistoryResult, error) {
	var res api.DeploymentLogsHistoryResult
	err := c.inv.invoke(ctx, "deployment.logsHistory", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) Errors(ctx context.Context, m *api.DeploymentErrors) (*api.DeploymentErrorsResult, error) {
	var res api.DeploymentErrorsResult
	err := c.inv.invoke(ctx, "deployment.errors", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) ErrorGet(ctx context.Context, m *api.DeploymentErrorGet) (*api.DeploymentErrorGetResult, error) {
	var res api.DeploymentErrorGetResult
	err := c.inv.invoke(ctx, "deployment.errorGet", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c deploymentClient) ErrorUpdate(ctx context.Context, m *api.DeploymentErrorUpdate) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "deployment.errorUpdate", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
