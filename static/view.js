var viewer;
var longPressTimer;
var touchStartX, touchStartY;
var hotspotsData = [];

document.addEventListener("DOMContentLoaded", function() {
    initializeViewer();
    setupTouchEvents(); // モバイル対応のためのタッチイベントのセットアップ
});

document.addEventListener('DOMContentLoaded', () => {
    const projectSelect = document.getElementById('projectSelect');
    projectSelect.addEventListener('change', () => {
        const projectId = projectSelect.value;
        if (projectId) {
            fetch(`/get_project_files/${projectId}`)
                .then(response => response.json())
                .then(data => {
                    console.log('Project files data:', data);
                    if (data.success) {
                        const projectFilesContainer = document.getElementById('projectFilesContainer');
                        const projectFiles = document.getElementById('projectFiles');
                        projectFiles.innerHTML = '';

                        let projectNameInput = document.getElementById('projectNameInput');
                        let saveProjectNameButton = document.getElementById('saveProjectNameButton');

                        if (!projectNameInput) {
                            projectNameInput = document.createElement('input');
                            projectNameInput.type = 'text';
                            projectNameInput.id = 'projectNameInput';
                            projectFilesContainer.appendChild(projectNameInput);
                        }
                        
                        projectNameInput.value = data.project.name;

                        if (!saveProjectNameButton) {
                            saveProjectNameButton = document.createElement('button');
                            saveProjectNameButton.innerText = 'Save Project Name';
                            saveProjectNameButton.id = 'saveProjectNameButton';
                            saveProjectNameButton.onclick = () => {
                                const newName = projectNameInput.value;
                                fetch(`/update_project_name/${projectId}`, {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'X-CSRFToken': '{{ csrf_token() }}'
                                    },
                                    body: JSON.stringify({ name: newName })
                                })
                                .then(response => response.json())
                                .then(data => {
                                    if (data.success) {
                                        alert('Project name updated successfully');
                                        projectSelect.options[projectSelect.selectedIndex].text = newName; // ドロップダウンの選択肢も更新
                                    } else {
                                        alert('Failed to update project name: ' + data.message);
                                    }
                                })
                                .catch(error => alert('Error: ' + error));
                            };
                            projectFilesContainer.appendChild(saveProjectNameButton);
                        }

                        data.files.forEach(file => {
                            const galleryItem = document.createElement('div');
                            galleryItem.className = 'gallery-item';

                            const shareCheckbox = document.createElement('input');
                            shareCheckbox.type = 'checkbox';
                            shareCheckbox.className = 'share-checkbox';
                            shareCheckbox.dataset.filename = file.filename;
                            shareCheckbox.checked = file.shared;
                            galleryItem.appendChild(shareCheckbox);

                            const projectCheckbox = document.createElement('input');
                            projectCheckbox.type = 'checkbox';
                            projectCheckbox.className = 'project-checkbox';
                            projectCheckbox.dataset.filename = file.filename;
                            galleryItem.appendChild(projectCheckbox);

                            const thumbnail = document.createElement('img');
                            thumbnail.className = 'thumbnail';
                            thumbnail.src = file.thumbnail;
                            thumbnail.alt = file.filename;
                            galleryItem.appendChild(thumbnail);

                            const detailsDiv = document.createElement('div');
                            const filenameP = document.createElement('p');
                            filenameP.innerText = file.filename;
                            detailsDiv.appendChild(filenameP);

                            const viewLink = document.createElement('a');
                            viewLink.href = `/view_image/${file.username}/${file.filename}`;
                            viewLink.className = 'view-button';
                            viewLink.innerText = 'View 360';
                            detailsDiv.appendChild(viewLink);

                            const deleteForm = document.createElement('form');
                            deleteForm.action = `/delete_file/${file.filename}`;
                            deleteForm.method = 'post';
                            deleteForm.style.display = 'inline';

                            const csrfInput = document.createElement('input');
                            csrfInput.type = 'hidden';
                            csrfInput.name = 'csrf_token';
                            csrfInput.value = '{{ csrf_token() }}';
                            deleteForm.appendChild(csrfInput);

                            const deleteButton = document.createElement('button');
                            deleteButton.type = 'submit';
                            deleteButton.innerText = 'Delete';
                            deleteForm.appendChild(deleteButton);

                            detailsDiv.appendChild(deleteForm);
                            galleryItem.appendChild(detailsDiv);

                            projectFiles.appendChild(galleryItem);

                            shareCheckbox.addEventListener('change', () => {
                                const filename = shareCheckbox.dataset.filename;
                                const shared = shareCheckbox.checked;
                                fetch('/update_share', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'X-CSRFToken': '{{ csrf_token() }}'
                                    },
                                    body: JSON.stringify({ filename, shared })
                                })
                                .then(response => response.json())
                                .then(data => {
                                    if (!data.success) {
                                        alert('Failed to update share status: ' + data.message);
                                    }
                                })
                                .catch(error => alert('Error: ' + error));
                            });
                        });

                        projectFilesContainer.style.display = 'block';
                    } else {
                        alert('Failed to load project files: ' + data.message);
                    }
                })
                .catch(error => {
                    console.error('Error fetching project files:', error);
                    alert('Error fetching project files: ' + error);
                });
        } else {
            document.getElementById('projectFilesContainer').style.display = 'none';
        }
    });

    const projectButton = document.getElementById('createProjectButton');
    projectButton.addEventListener('click', () => {
        const selectedFiles = [];
        document.querySelectorAll('.project-checkbox:checked').forEach(checkbox => {
            selectedFiles.push(checkbox.dataset.filename);
        });

        fetch('/create_project', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': '{{ csrf_token() }}'
            },
            body: JSON.stringify({ files: selectedFiles })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.reload();
            } else {
                alert('Failed to create project: ' + data.message);
            }
        })
        .catch(error => alert('Error: ' + error));
    });

    const checkboxes = document.querySelectorAll('.share-checkbox');
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', () => {
            const filename = checkbox.dataset.filename;
            const shared = checkbox.checked;
            fetch('/update_share', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': '{{ csrf_token() }}'
                },
                body: JSON.stringify({ filename, shared })
            })
            .then(response => response.json())
            .then(data => {
                if (!data.success) {
                    alert('Failed to update share status: ' + data.message);
                }
            })
            .catch(error => alert('Error: ' + error));
        });
    });
});

window.addEventListener("resize", function() {
    if (viewer) {
        viewer.resize();
    }
});

function initializeViewer() {
    viewer = pannellum.viewer('panorama', {
        "type": "equirectangular",
        "panorama": imageUrl,
        "autoLoad": true
    });

    // iOSフルスクリーンサポートを追加
    if (navigator.userAgent.match(/(iPod|iPhone|iPad)/)) {
        var fullscreenButton = document.querySelector('.pnlm-fullscreen-toggle-button');
        if (fullscreenButton) {
            fullscreenButton.addEventListener('click', function () {
                if (viewer.isFullscreen()) {
                    viewer.exitFullscreen();
                } else {
                    viewer.requestFullscreen();
                }
            });
        }
    }

    // 直後にloadHotspots関数を呼び出す
    loadHotspots();

    // 必要に応じてタイムアウト遅延を増加
    setTimeout(loadHotspots, 500); // 250ミリ秒から500ミリ秒に増加

    setupContextMenu();
}

function createCustomTooltip(hotSpotDiv, args) {
    const span = document.createElement('span');
    span.classList.add('custom-hotspot-tooltip');
    span.innerText = args.text;
    hotSpotDiv.appendChild(span);

    // URLが存在する場合、リンクとして表示
    if (args.url) {
        const link = document.createElement('span');
        link.classList.add('custom-hotspot-url');
        link.innerText = "Link";
        hotSpotDiv.appendChild(link);
    }

    // サムネイル画像が存在する場合、表示
    if (args.thumbnail) {
        const img = document.createElement('img');
        img.classList.add('custom-hotspot-thumbnail');
        img.src = args.thumbnail;
        hotSpotDiv.appendChild(img);

        img.addEventListener('click', function(event) {
            event.stopPropagation();
            window.location.href = `/hotspot_info/${args.id}`;
        });
    }

    // ホットスポットに右クリックイベントを追加
    hotSpotDiv.addEventListener('contextmenu', function(event) {
        event.preventDefault();
        hotspotClicked(args);
    });

    // ホットスポットに左クリックイベントを追加
    hotSpotDiv.addEventListener('click', function() {
        window.location.href = `/hotspot_info/${args.id}`;
    });
}

function loadHotspots() {
    fetch(`/hotspots?image_id=${filename}`)
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        hotspotsData = data;
        updateHotspotList();
        data.forEach(hotspot => {
            if (hotspot.description) {  // descriptionがnullでない場合にのみ表示
                viewer.addHotSpot({
                    "pitch": hotspot.pitch,
                    "yaw": hotspot.yaw,
                    "type": "custom",
                    "cssClass": "custom-hotspot",
                    "createTooltipFunc": createCustomTooltip,
                    "createTooltipArgs": {
                        "text": hotspot.description,
                        "pitch": hotspot.pitch,
                        "yaw": hotspot.yaw,
                        "id": hotspot.id,
                        "additional_text": hotspot.additional_text,
                        "url": hotspot.url,
                        "thumbnail": hotspot.thumbnail_path // サムネイルパスをそのまま使用
                    }
                });
            }
        });
    })
    .catch(error => console.error('Error fetching hotspots:', error));
}

function updateHotspotList() {
    const hotspotList = document.getElementById('hotspotItems');
    const hotspotCount = document.getElementById('hotspotCount');
    hotspotList.innerHTML = '';
    hotspotCount.innerText = hotspotsData.length;

    hotspotsData.forEach(hotspot => {
        if (hotspot.description) { // descriptionがnullでない場合にのみリストに追加
            const item = document.createElement('div');
            item.classList.add('hotspot-item');
            item.innerText = hotspot.description;
            item.onclick = () => {
                viewer.lookAt(hotspot.pitch, hotspot.yaw);
            };
            hotspotList.appendChild(item);
        }
    });
}

function setupContextMenu() {
    document.getElementById('panorama').addEventListener('contextmenu', function(event) {
        event.preventDefault();
        var coords = viewer.mouseEventToCoords(event);
        var existingHotspot = findExistingHotspot(coords[0], coords[1]);
        if (existingHotspot) {
            hotspotClicked(existingHotspot);
        } else {
            showCommentForm(coords[0], coords[1], null);
        }
    });
}

function setupTouchEvents() {
    var panorama = document.getElementById('panorama');
    
    panorama.addEventListener('touchstart', function(event) {
        var touch = event.touches[0];
        touchStartX = touch.clientX;
        touchStartY = touch.clientY;
        longPressTimer = setTimeout(function() {
            handleTouchEvent(touchStartX, touchStartY);
        }, 500); // 長押しを検出する時間（500ミリ秒）
    });

    panorama.addEventListener('touchend', function(event) {
        clearTimeout(longPressTimer);
    });

    panorama.addEventListener('touchmove', function(event) {
        clearTimeout(longPressTimer);
    });

    // ピンチイン・ピンチアウトイベントの追加
    panorama.addEventListener('gesturestart', function(event) {
        event.preventDefault();
    });

    panorama.addEventListener('gesturechange', function(event) {
        event.preventDefault();
    });

    panorama.addEventListener('gestureend', function(event) {
        event.preventDefault();
    });
}

function handleTouchEvent(clientX, clientY) {
    var coords = viewer.mouseEventToCoords({ clientX: clientX, clientY: clientY });
    var existingHotspot = findExistingHotspot(coords[0], coords[1]);
    if (existingHotspot) {
        hotspotClicked(existingHotspot);
    } else {
        showCommentForm(coords[0], coords[1], null);
    }
}

function hotspotClicked(args) {
    showCommentForm(args.pitch, args.yaw, args);
}

function showCommentForm(pitch, yaw, hotspot) {
    var form = document.getElementById('commentForm');
    form.style.display = 'block';
    document.getElementById('commentText').value = hotspot ? hotspot.description : '';
    document.getElementById('additionalText').value = hotspot ? hotspot.additional_text : '';
    document.getElementById('urlText').value = hotspot ? hotspot.url : '';  // URLフィールドの値を設定
    document.getElementById('uploadComment').value = hotspot ? hotspot.upload_comment : '';  // 画像コメントの値を設定
    form.dataset.pitch = pitch;
    form.dataset.yaw = yaw;
    form.dataset.hotspotId = hotspot ? hotspot.id : '';
    
    // URLが存在する場合、"Check"ボタンを表示
    var checkButton = document.getElementById('checkButton');
    if (hotspot && hotspot.url) {
        checkButton.style.display = 'inline-block';
    } else {
        checkButton.style.display = 'none';
    }
}

function findExistingHotspot(pitch, yaw) {
    return hotspotsData.find(hotspot => 
        Math.abs(hotspot.pitch - pitch) < 1 && 
        Math.abs(hotspot.yaw - yaw) < 1
    );
}

function saveComment() {
    var form = document.getElementById('commentForm');
    var text = document.getElementById('commentText').value;
    var additionalText = document.getElementById('additionalText').value;
    var url = document.getElementById('urlText').value;  // URLフィールドの値を取得
    var uploadComment = document.getElementById('uploadComment').value;  // 画像コメントの値を取得
    var pitch = parseFloat(form.dataset.pitch);
    var yaw = parseFloat(form.dataset.yaw);
    var id = form.dataset.hotspotId;
    var imageId = filename;  // Flaskテンプレートから値を取得していることを確認
    var imageFile = document.getElementById('imageUpload').files[0];

    if (!text && !additionalText && !url && !imageFile && !uploadComment) {
        alert('Please enter at least one field.');
        return;
    }

    var formData = new FormData();
    formData.append('pitch', pitch);
    formData.append('yaw', yaw);
    formData.append('text', text);
    formData.append('additional_text', additionalText);
    formData.append('url', url);
    formData.append('image_id', imageId);
    formData.append('upload_comment', uploadComment);  // 画像コメントを追加
    if (imageFile) {
        formData.append('image_file', imageFile);
    }
    formData.append('csrf_token', csrfToken);

    fetch(id ? `/update_hotspot/${id}` : '/save_hotspot', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            loadHotspots();
            form.style.display = 'none';
            document.getElementById('commentText').value = '';
            document.getElementById('additionalText').value = '';
            document.getElementById('urlText').value = '';  // URLフィールドの値をクリア
            document.getElementById('imageUpload').value = ''; // 画像フィールドの値をクリア
            document.getElementById('uploadComment').value = ''; // 画像コメントの値をクリア
            document.getElementById('checkButton').style.display = 'none';  // "Check"ボタンを非表示
        } else {
            console.error('Error:', data.message);
        }
    })
    .catch(error => console.error('Error:', error));
}

function cancelEdit() {
    var form = document.getElementById('commentForm');
    form.style.display = 'none';
    document.getElementById('commentText').value = '';
    document.getElementById('additionalText').value = '';
    document.getElementById('urlText').value = '';  // URLフィールドの値をクリア
    document.getElementById('imageUpload').value = ''; // 画像フィールドの値をクリア
    document.getElementById('uploadComment').value = ''; // 画像コメントの値をクリア
    document.getElementById('checkButton').style.display = 'none';  // "Check"ボタンを非表示
}

function checkUrl() {
    var url = document.getElementById('urlText').value;
    if (url) {
        window.open(url, '_blank');
    }
}
