import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Attack, Model, ModelCreate, ModelTestResult, RedTeamSession, Result, Run, ScanResult } from "../api/types";

// ---- Models ----
export function useModels() {
  return useQuery({ queryKey: ["models"], queryFn: () => api.get<Model[]>("/models") });
}

export function useCreateModel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ModelCreate) => api.post<Model>("/models", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["models"] }),
  });
}

export function useDeleteModel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del(`/models/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["models"] }),
  });
}

export function useTestModel() {
  return useMutation({
    mutationFn: (id: string) => api.post<ModelTestResult>(`/models/${id}/test`),
  });
}

// ---- Attacks ----
export function useAttacks() {
  return useQuery({ queryKey: ["attacks"], queryFn: () => api.get<Attack[]>("/attacks") });
}

// ---- Runs ----
export function useRuns() {
  return useQuery({ queryKey: ["runs"], queryFn: () => api.get<Run[]>("/runs") });
}

export function useRun(id: string | undefined) {
  return useQuery({
    queryKey: ["run", id],
    queryFn: () => api.get<Run>(`/runs/${id}`),
    enabled: !!id,
    refetchInterval: (query) => (query.state.data?.status === "running" ? 1500 : false),
  });
}

export function useRunResults(id: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ["run-results", id],
    queryFn: () => api.get<Result[]>(`/runs/${id}/results`),
    enabled: !!id && enabled,
  });
}

export function useCreateRun() {
  return useMutation({
    mutationFn: (body: {
      model_id: string;
      attack_ids?: string[];
      use_llm_judge?: boolean;
      samples?: number;
    }) => api.post<Run>("/runs", body),
  });
}

// ---- Red Team ----
export function useRedTeamSessions() {
  return useQuery({ queryKey: ["redteam"], queryFn: () => api.get<RedTeamSession[]>("/redteam") });
}

export function useRedTeamSession(id: string | undefined) {
  return useQuery({
    queryKey: ["redteam", id],
    queryFn: () => api.get<RedTeamSession>(`/redteam/${id}`),
    enabled: !!id,
    refetchInterval: (query) => (query.state.data?.status === "running" ? 2000 : false),
  });
}

export function useCreateRedTeam() {
  return useMutation({
    mutationFn: (body: { target_model_id: string; objective: string; max_rounds?: number; attacker_model_id?: string }) =>
      api.post<RedTeamSession>("/redteam", body),
  });
}

// ---- Repo / Web scanners ----
function scanHooks(kind: "repo" | "web") {
  return {
    useList: () => useQuery({ queryKey: [`${kind}-scans`], queryFn: () => api.get<ScanResult[]>(`/scan/${kind}`) }),
    useOne: (id: string | undefined) =>
      useQuery({
        queryKey: [`${kind}-scan`, id],
        queryFn: () => api.get<ScanResult>(`/scan/${kind}/${id}`),
        enabled: !!id,
        refetchInterval: (q) => (q.state.data?.status === "running" ? 1500 : false),
      }),
  };
}

const repo = scanHooks("repo");
const web = scanHooks("web");

export const useRepoScans = repo.useList;
export const useRepoScan = repo.useOne;
export const useWebScans = web.useList;
export const useWebScan = web.useOne;

export function useCreateRepoScan() {
  return useMutation({
    mutationFn: (body: { repo_url: string; use_ai?: boolean; reviewer_model_id?: string }) =>
      api.post<ScanResult>("/scan/repo", body),
  });
}

export function useCreateWebScan() {
  return useMutation({
    mutationFn: (body: { target_url: string; authorized?: boolean; use_ai?: boolean; reviewer_model_id?: string }) =>
      api.post<ScanResult>("/scan/web", body),
  });
}
