package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	//"time"

	v1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

type result struct {
	namespace   string
	resource    string
	verb        string
	allowed     bool
	account     string
	accountType string
}

type job struct {
	namespace   string
	resource    string
	verb        string
	namespaced  bool
	account     string
	accountType string
}

func checkAccess(clientset *kubernetes.Clientset, namespace, resource, verb string, namespaced bool, account string, accountType string, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()

	var resourceAttributes *v1.ResourceAttributes
	if namespaced {
		resourceAttributes = &v1.ResourceAttributes{
			Namespace: namespace,
			Verb:      verb,
			Resource:  resource,
		}
	} else {
		resourceAttributes = &v1.ResourceAttributes{
			Verb:     verb,
			Resource: resource,
		}
	}

	ssar := &v1.SelfSubjectAccessReview{
		Spec: v1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: resourceAttributes,
		},
	}

	response, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(context.Background(), ssar, metav1.CreateOptions{})
	if err != nil {
		log.Printf("Failed to create SelfSubjectAccessReview for verb %s on resource %s: %v", verb, resource, err)
		resultsChan <- result{
			namespace:   namespace,
			resource:    resource,
			verb:        verb,
			allowed:     false,
			account:     account,
			accountType: accountType,
		}
		return
	}

	resultsChan <- result{
		namespace:   namespace,
		resource:    resource,
		verb:        verb,
		allowed:     response.Status.Allowed,
		account:     account,
		accountType: accountType,
	}
}

func worker(clientset *kubernetes.Clientset, jobsChan <-chan job, resultsChan chan<- result, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobsChan {
		checkAccess(clientset, job.namespace, job.resource, job.verb, job.namespaced, job.account, job.accountType, resultsChan, wg)
	}
}

func getAPIResources(clientset *kubernetes.Clientset) (map[string]bool, map[string]bool, error) {
	discoveryClient := clientset.Discovery()
	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil && discovery.IsGroupDiscoveryFailedError(err) {
		log.Printf("Partial discovery error: %v", err)
	}

	namespacedResources := make(map[string]bool)
	nonNamespacedResources := make(map[string]bool)

	for _, apiResourceList := range apiResourceLists {
		for _, apiResource := range apiResourceList.APIResources {
			if !strings.Contains(apiResource.Name, "/") { // Filter out subresources
				if apiResource.Namespaced {
					namespacedResources[apiResource.Name] = true
				} else {
					nonNamespacedResources[apiResource.Name] = true
				}
			}
		}
	}
	return namespacedResources, nonNamespacedResources, nil
}

func checkClusterLevelPermissions(clientset *kubernetes.Clientset, resource string, verbs []string, account string, accountType string) (bool, map[string]string) {
	results := make(map[string]string)
	for _, verb := range verbs {
		ssar := &v1.SelfSubjectAccessReview{
			Spec: v1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &v1.ResourceAttributes{
					Verb:     verb,
					Resource: resource,
				},
			},
		}

		response, err := clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(context.Background(), ssar, metav1.CreateOptions{})
		if err != nil || !response.Status.Allowed {
			results[verb] = text.FgRed.Sprintf("X")
		} else {
			results[verb] = text.FgGreen.Sprintf("V")
		}
	}
	for _, status := range results {
		if status == text.FgRed.Sprintf("X") {
			return false, results
		}
	}
	return true, results
}

func enumerateSubjects(clientset *kubernetes.Clientset) ([]string, []string, error) {
	roleBindings, err := clientset.RbacV1().RoleBindings("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list RoleBindings: %v", err)
	}

	clusterRoleBindings, err := clientset.RbacV1().ClusterRoleBindings().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list ClusterRoleBindings: %v", err)
	}

	users := make(map[string]struct{})
	serviceAccounts := make(map[string]struct{})

	for _, rb := range roleBindings.Items {
		for _, subject := range rb.Subjects {
			if subject.Kind == rbacv1.UserKind {
				users[subject.Name] = struct{}{}
			} else if subject.Kind == rbacv1.ServiceAccountKind {
				sa := fmt.Sprintf("%s:%s", subject.Namespace, subject.Name)
				serviceAccounts[sa] = struct{}{}
			}
		}
	}

	for _, crb := range clusterRoleBindings.Items {
		for _, subject := range crb.Subjects {
			if subject.Kind == rbacv1.UserKind {
				users[subject.Name] = struct{}{}
			} else if subject.Kind == rbacv1.ServiceAccountKind {
				sa := fmt.Sprintf("%s:%s", subject.Namespace, subject.Name)
				serviceAccounts[sa] = struct{}{}
			}
		}
	}

	userList := make([]string, 0, len(users))
	for user := range users {
		userList = append(userList, user)
	}

	serviceAccountList := make([]string, 0, len(serviceAccounts))
	for sa := range serviceAccounts {
		serviceAccountList = append(serviceAccountList, sa)
	}

	return userList, serviceAccountList, nil
}

func filterOutKubeSystem(accounts []string) []string {
	var filtered []string
	for _, account := range accounts {
		if !strings.Contains(account, "kube-system:") && !strings.Contains(account, "system:") {
			filtered = append(filtered, account)
		}
	}
	return filtered
}

func readUsersFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		user := strings.TrimSpace(scanner.Text())
		if user != "" {
			users = append(users, user)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func main() {
	var usernames flagSlice
	var serviceAccounts flagSlice
	var kubeconfig, usersFile string
	noKubeSystem := flag.Bool("no-kube-system", false, "Do not check resources in the kube-system namespace")
	flag.Var(&usernames, "as", "Usernames to impersonate")
	flag.Var(&serviceAccounts, "sa", "Service accounts to impersonate in the format namespace:serviceaccount")
	self := flag.Bool("self", false, "Use current kubeconfig context")
	auto := flag.Bool("auto", false, "Automatically enumerate all Users and ServiceAccounts in RoleBindings and ClusterRoleBindings")
	flag.StringVar(&kubeconfig, "kubeconfig", os.Getenv("HOME")+"/.kube/config", "Path to the kubeconfig file")
	flag.StringVar(&usersFile, "f", "", "Path to a file containing a list of users to check")
	flag.Parse()

	// Check for flag conflicts
	if *self && (len(usernames) > 0 || len(serviceAccounts) > 0) {
		log.Fatalf("You cannot use -as or -sa flags with -self")
	}

	// Create a clientset without impersonation to list all namespaces and resources
	defaultConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Failed to build default kubeconfig: %v", err)
	}

	// Increase QPS and Burst for the default client
	defaultConfig.QPS = 10000
	defaultConfig.Burst = 20000

	defaultClientset, err := kubernetes.NewForConfig(defaultConfig)
	if err != nil {
		log.Fatalf("Failed to create default Kubernetes client: %v", err)
	}

	var autoUsernames, autoServiceAccounts, fileUsernames []string
	if *auto {
		autoUsernames, autoServiceAccounts, err = enumerateSubjects(defaultClientset)
		if err != nil {
			log.Fatalf("Failed to enumerate subjects: %v", err)
		}
	}

	if usersFile != "" {
		fileUsernames, err = readUsersFromFile(usersFile)
		if err != nil {
			log.Fatalf("Failed to read users from file: %v", err)
		}
	}

	if len(usernames) == 0 && len(serviceAccounts) == 0 && len(fileUsernames) == 0 && !*self && !*auto {
		log.Fatalf("You must specify at least one username with the --as flag, a service account with the --sa flag, use the --self flag, use the --auto flag, or specify a users file with the -f flag")
	}

	// List all namespaces using the default clientset
	namespaces, err := defaultClientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatalf("Failed to list namespaces: %v", err)
	}

	// Get all API resources (both namespaced and non-namespaced) using the default clientset
	namespacedResources, nonNamespacedResources, err := getAPIResources(defaultClientset)
	if err != nil {
		log.Fatalf("Failed to get API resources: %v", err)
	}

	verbs := []string{"create", "get", "list", "watch", "patch", "update", "delete"}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	header := table.Row{"ACCOUNT", "TYPE", "NAMESPACE", "RESOURCE", "CREATE", "GET", "LIST", "WATCH", "PATCH", "UPDATE", "DELETE"}
	t.AppendHeader(header)

	processAccounts := func(accounts []string, accountType string) {
		for _, account := range accounts {
			var clientset *kubernetes.Clientset
			var impersonatedConfig *rest.Config
			if *self {
				// Use the default clientset for self-checks
				clientset = defaultClientset
			} else {
				// Create an impersonated clientset for the specified user or service account
				impersonatedConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
				if err != nil {
					log.Fatalf("Failed to build impersonated kubeconfig: %v", err)
				}

				if accountType == "U" {
					impersonatedConfig.Impersonate.UserName = account
				} else if accountType == "SA" {
					saParts := strings.Split(account, ":")
					if len(saParts) != 2 {
						log.Fatalf("Service account must be in the format namespace:serviceaccount")
					}
					impersonatedConfig.Impersonate.UserName = fmt.Sprintf("system:serviceaccount:%s:%s", saParts[0], saParts[1])
				}

				// Increase QPS and Burst for the impersonated client
				impersonatedConfig.QPS = 10000
				impersonatedConfig.Burst = 20000

				clientset, err = kubernetes.NewForConfig(impersonatedConfig)
				if err != nil {
					log.Fatalf("Failed to create impersonated Kubernetes client: %v", err)
				}
			}

			resultsChan := make(chan result)
			jobsChan := make(chan job)
			var wg sync.WaitGroup

			//start := time.Now()

			// Start a fixed number of worker goroutines
			numWorkers := 50
			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go worker(clientset, jobsChan, resultsChan, &wg)
			}

			clusterLevelAllowed := make(map[string]bool)
			clusterLevelResults := make(map[string]map[string]string)

			// Check cluster-level permissions for each resource
			for resource := range namespacedResources {
				allowed, results := checkClusterLevelPermissions(clientset, resource, verbs, account, accountType)
				if allowed {
					clusterLevelAllowed[resource] = true
					clusterLevelResults[resource] = results
				} else {
					clusterLevelAllowed[resource] = false
				}
			}

			for resource := range nonNamespacedResources {
				allowed, results := checkClusterLevelPermissions(clientset, resource, verbs, account, accountType)
				if allowed {
					clusterLevelAllowed[resource] = true
					clusterLevelResults[resource] = results
				} else {
					clusterLevelAllowed[resource] = false
				}
			}

			// Enqueue jobs for namespaced resources if not fully allowed at the cluster level
			go func() {
				for _, ns := range namespaces.Items {
					if *noKubeSystem && ns.Name == "kube-system" {
						continue
					}
					for resource := range namespacedResources {
						if !clusterLevelAllowed[resource] {
							for _, verb := range verbs {
								wg.Add(1)
								jobsChan <- job{namespace: ns.Name, resource: resource, verb: verb, namespaced: true, account: account, accountType: accountType}
							}
						}
					}
				}
				// Enqueue jobs for non-namespaced resources
				for resource := range nonNamespacedResources {
					if !clusterLevelAllowed[resource] {
						for _, verb := range verbs {
							wg.Add(1)
							jobsChan <- job{namespace: "", resource: resource, verb: verb, namespaced: false, account: account, accountType: accountType}
						}
					}
				}
				close(jobsChan)
			}()

			// Collect results
			var resultsWg sync.WaitGroup
			resultsWg.Add(1)
			go func() {
				defer resultsWg.Done()
				resultsMap := make(map[string]map[string]map[string]string)
				namespacePermissions := make(map[string]map[string]map[string]bool)
				for res := range resultsChan {
					nsKey := res.namespace
					if res.namespace == "" {
						nsKey = "CLUSTER"
					}
					if resultsMap[nsKey] == nil {
						resultsMap[nsKey] = make(map[string]map[string]string)
					}
					if resultsMap[nsKey][res.resource] == nil {
						resultsMap[nsKey][res.resource] = make(map[string]string)
					}
					if namespacePermissions[res.resource] == nil {
						namespacePermissions[res.resource] = make(map[string]map[string]bool)
					}
					if namespacePermissions[res.resource][res.verb] == nil {
						namespacePermissions[res.resource][res.verb] = make(map[string]bool)
					}
					namespacePermissions[res.resource][res.verb][res.namespace] = res.allowed

					if res.allowed {
						resultsMap[nsKey][res.resource][res.verb] = text.FgGreen.Sprintf("V")
					} else {
						resultsMap[nsKey][res.resource][res.verb] = text.FgRed.Sprintf("X")
					}
				}

				// Include cluster-level results
				for resource, results := range clusterLevelResults {
					if resultsMap["CLUSTER"] == nil {
						resultsMap["CLUSTER"] = make(map[string]map[string]string)
					}
					resultsMap["CLUSTER"][resource] = results
				}

				// Detect common permissions across all namespaces and consolidate as CLUSTER scope
				for resource, verbs := range namespacePermissions {
					for verb, namespaces := range verbs {
						allNamespaces := true
						for ns := range namespaces {
							if !namespaces[ns] {
								allNamespaces = false
								break
							}
						}
						if allNamespaces {
							if resultsMap["CLUSTER"] == nil {
								resultsMap["CLUSTER"] = make(map[string]map[string]string)
							}
							if resultsMap["CLUSTER"][resource] == nil {
								resultsMap["CLUSTER"][resource] = make(map[string]string)
							}
							resultsMap["CLUSTER"][resource][verb] = text.FgGreen.Sprintf("V")
							// Remove the permission from all namespaces
							for ns := range namespaces {
								if ns != "" {
									delete(resultsMap[ns], resource)
								}
							}
						}
					}
				}

				for ns, resources := range resultsMap {
					for resource, verbs := range resources {
						var row table.Row
						if *self {
							row = table.Row{"", "", ns, resource}
						} else {
							row = table.Row{account, accountType, ns, resource}
						}
						// Remove verbose-related logic
						allDisabled := true
						for _, verb := range []string{"create", "get", "list", "watch", "patch", "update", "delete"} {
							if verbs[verb] == "" {
								verbs[verb] = text.FgRed.Sprintf("X")
							}
							row = append(row, verbs[verb])
							if verbs[verb] == text.FgGreen.Sprintf("V") {
								allDisabled = false
							}
						}
						if !allDisabled {
							t.AppendRow(row)
						}
					}
				}
			}()

			// Wait for all jobs to be processed
			wg.Wait()
			close(resultsChan)
			resultsWg.Wait()

			//fmt.Printf("Completed checks for %s in %v\n", account, time.Since(start))
		}
	}

	if *self {
		processAccounts([]string{""}, "")
	} else if *auto {
		if *noKubeSystem {
			filteredUsers := filterOutKubeSystem(autoUsernames)
			processAccounts(filteredUsers, "U")
			filteredServiceAccounts := filterOutKubeSystem(autoServiceAccounts)
			processAccounts(filteredServiceAccounts, "SA")
		} else {
			processAccounts(autoUsernames, "U")
			processAccounts(autoServiceAccounts, "SA")
		}
	} else {
		processAccounts(usernames, "U")
		processAccounts(serviceAccounts, "SA")
		processAccounts(fileUsernames, "U")
	}

	t.Render()
}

type flagSlice []string

func (i *flagSlice) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *flagSlice) Set(value string) error {
	*i = append(*i, value)
	return nil
}
