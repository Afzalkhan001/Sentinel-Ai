import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Attack, Model, ModelCreate, ModelTestResult, RedTeamSession, Result, Run } from "../api/types";

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
    mutationFn: (body: { model_id: string; attack_ids?: string[]; use_llm_judge?: boolean }) =>
      api.post<Run>("/runs", body),
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
