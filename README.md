# threatspec

## Getting started

### Step 1 - Install threatspec

```
$ pip install threatspec
```

### Step 2 - Initialise threatspec in your code repository

```
$ threatspec init
```

You can edit the `.threatspec.yaml` file.

### Step 3 - Run threatspecc

```
$ threatspec run
```

### Step 4 - Generate the threat model report

```
$ threatspec report
```

Threatspec will create a number of files:

  * ThreatModel.md
  * threatmodel/threatmodel.json
  * threatmodel/threats.json
  * threatmodel/controls.json
  * threatmodel/components.json
