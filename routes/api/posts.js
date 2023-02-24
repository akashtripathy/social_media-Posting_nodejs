const express = require('express');
const router = express.Router();
const  {check,validationResult} = require('express-validator');
const auth = require('../../middleware/auth');

const Post = require('../../models/Post');
const User = require('../../models/User');
const Profile = require('../../models/Profile');

// @route   POST api/posts
// @desc    Create a post
// @access  Private
router.post('/',[auth,[
    check('text','Text is required').not().isEmpty()
]],async(req,res)=> {
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        return res.status(400).json({error: errors.array()});
    }

    try {
        const user = await User.findById(req.user.id).select('-password');

        const newPost = new Post({
            text: req.body.text,
            name: user.name,
            avatar: user.avatar,
            user: req.user.id
        });

        const post = await newPost.save();

        res.json(post);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }

});

// @route   GET api/posts
// @desc    Get all post
// @access  Private
router.get('/',auth , async(req,res)=>{
    try {
        const posts = await Post.find().sort({date: -1});
        res.json(posts);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   GET api/posts/:id
// @desc    Get post by ID
// @access  Private
router.get('/:id',auth , async(req,res)=>{
    try {
        const post = await Post.findById(req.params.id);

        if(!post){
            return res.status(400).json({msg: 'Post not fornd'});
        }
        res.json(post);
    } catch (err) {
        console.error(err.message);
        if(err.kind === 'ObjectId'){
            return res.status(400).json({msg: 'Post not fornd'});
        }
        res.status(500).send('Server error');
    }
});

// @route   DELETE api/posts/:id
// @desc    Delete a post by ID
// @access  Private
router.delete('/:id',auth , async(req,res)=>{
    try {
        const post = await Post.findById(req.params.id);

        if(!post){
            return res.status(400).json({msg: 'Post not fornd'});
        }

        //Check if user is authenticate user or not
        if(post.user.toString() !== req.user.id){
            return res.sendStatus(401).json({msg: 'User not authorized'});
        }

        await post.remove();

        res.json({msg: 'Post removed'});
    } catch (err) {
        console.error(err.message);
        if(err.kind === 'ObjectId'){
            return res.status(400).json({msg: 'Post not fornd'});
        }
        res.status(500).send('Server error');
    }
});

// @route   PUT api/posts/like/:id
// @desc    Delete a post by ID
// @access  Private
router.put('/like/:id', auth, async(req,res)=>{
    try {
        const post = await Post.findById(req.params.id);

        //check if the post has already liked
        if(post.likes.filter(like => like.user.toString() === req.user.id).length > 0){
            return res.status(400).json({msg: 'Post already liked'});
        }

        post.likes.unshift({user: req.user.id});

        await post.save();

        res.json(post.likes);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   PUT api/posts/unlike/:id
// @desc    Delete a post by ID
// @access  Private
router.put('/unlike/:id', auth, async(req,res)=>{
    try {
        const post = await Post.findById(req.params.id);

        //check if the post has already liked
        if(post.likes.filter(like => like.user.toString() === req.user.id).length === 0){
            return res.status(400).json({msg: 'Post has not yet been liked'});
        }

        // Get remove index
        const removeIndex = post.likes.map(like=> like.user.toString()).indexOf(req.user.id);

        post.likes.splice(removeIndex, 1);

        await post.save();

        res.json(post.likes);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   POST api/posts/comment/:id
// @desc    Comment on a post
// @access  Private
router.post('/comment/:id',[auth,[
    check('text','Text is required').not().isEmpty()
]],async(req,res)=> {
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        return res.status(400).json({error: errors.array()});
    }

    try {
        const user = await User.findById(req.user.id).select('-password');
        const post = await Post.findById(req.params.id);

        const newComment = {
            text: req.body.text,
            name: user.name,
            avatar: user.avatar,
            user: req.user.id
        };

        post.comment.unshift(newComment);

        await post.save();

        res.json(post.comment);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   DELETE api/posts/comment/:id/:comment_id
// @desc    Delete comment
// @access  Private
router.delete('/comment/:id/:comment_id',auth, async(req,res)=>{
    try {
        const post = await Post.findById(req.params.id);

        // Pull out comment
        const comment = post.comment.find(comment=> comment.id === req.params.comment_id);

        // Make sure comment exist
        if(!comment){
            return res.status(404).json({msg: 'Comment does not exist'});
        }

        // Check user
        if(comment.user.toString() !== req.user.id){
            return res.status(404).json({msg: 'User not authorized'});
        }

        // Get remove index
        const removeIndex = post.comment.map(comment=> comment.user.toString()).indexOf(req.user.id);

        post.comment.splice(removeIndex, 1);

        await post.save();

        res.json(post.comment);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
})

module.exports = router;