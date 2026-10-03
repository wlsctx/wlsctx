variable "REGISTRY" {
  default = "localhost"
}

variable "REPO" {
  default = "wlsctx"
}

variable "DISTRO_RELEASE" {
  default = "43"
}

function "today" {
  params = []
  result = formatdate("YYYYMMDD", timestamp())
}

function "tags" {
  params = [img]
  result = distinct([
    "${img}:latest",
    notequal("",TAG) ? "${img}:${TAG}": ""
  ])
}

variable "TAG" {
  default = "${DISTRO_RELEASE}." + today()
}

group "default" {
  targets = [
    "runtime",
    "devel",
  ]
}

target "_runtime_common" {
  dockerfile = "Containerfile"
  context = "apps/runtime"
  contexts = {
    fedora = "docker-image://registry.fedoraproject.org/fedora:${DISTRO_RELEASE}"
  }
}

target "runtime" {
  inherits = ["_runtime_common"]
  matrix = {
    tgt = ["shell", "wayland", "java-wayland", "java-headless"]
  }
  name = "${tgt}-runtime"
  target = "${tgt}-runtime"
  tags = tags("${tgt}-runtime")
}


target "devel" {
  inherits = ["_runtime_common"]
  matrix = {
    tgt = ["shell"]
  }
  name = "${tgt}-devel"
  target = "${tgt}-devel"
  tags = tags("${tgt}-devel")
}
