# 给人用的集群账号。
#
# token 由 k8s 填进 hank-token 这个 Secret，取出来后存在
# secrets/clients/kube-tank.yaml（只加密给 hank 自己），home/users/hank/modules/kube 用它生成
# kubeconfig。这个 token 不会过期，撤销的办法是删掉 hank-token，k8s 会再签一个新的。
{
  applications.access = {
    namespace = "kube-system";
    createNamespace = false;

    resources = {
      serviceAccounts.hank = {};

      secrets.hank-token = {
        type = "kubernetes.io/service-account-token";
        metadata.annotations."kubernetes.io/service-account.name" = "hank";
      };

      clusterRoleBindings.hank-cluster-admin = {
        roleRef = {
          apiGroup = "rbac.authorization.k8s.io";
          kind = "ClusterRole";
          name = "cluster-admin";
        };
        subjects = [
          {
            kind = "ServiceAccount";
            name = "hank";
            namespace = "kube-system";
          }
        ];
      };
    };

    # data 是 k8s 的 token 控制器填的，不是渲染出来的，别让 Argo CD 当成漂移。
    ignoreDifferences.Secret = {
      name = "hank-token";
      jsonPointers = ["/data"];
    };
  };
}
