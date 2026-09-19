# TraceWard Development Workflow

## Branch Structure

- **`main`**: Stable and tested project versions only. No direct feature development.
- **`dev`**: Team integration branch. Completed features are reviewed here before merging into `main`.
- **`feature branches`**: Each member develops their assigned work in a separate branch created from `dev`.

## Team Contribution Rules

1. Pull the latest `dev` before starting a task.
2. Each member must create and work on their own feature branch.
3. Each member must commit using their own GitHub-linked name and email.
4. Do not commit using another member's identity.
5. Do not develop features directly on `main`.
6. Do not develop assigned features directly on `dev`.
7. Push the feature branch to GitHub after testing.
8. Create a Pull Request from the feature branch into `dev`.
9. Team Lead reviews integration before merging.
10. `main` receives only tested versions from `dev`.
11. Never use force push on shared branches unless the team explicitly agrees.
12. Avoid editing another member's primary module unless discussed first.

## Planned Member Branches

- **Member 2**: `feature/kmeans-clustering`
- **Member 3**: `feature/knn-risk-prediction`
- **Member 4**: `feature/network-astar`
- **Member 5**: `feature/csp-dashboard`

> **Note**: These branches should be **created by the members themselves** from their own GitHub accounts when they start their work.
